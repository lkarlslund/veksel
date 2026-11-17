// veksel is a lightweight self-hosted email and data server.
//
//go:generate go mod tidy
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/lkarlslund/veksel/pkg/log"
)

// Set by build ldflags.
var (
	buildVersion = "dev"
	buildTime    = "unknown"
	buildCommit  = "unknown"
)

func writeBuildVersion(writer io.Writer) {
	_, _ = fmt.Fprintf(writer, "veksel %s\ncommit %s\nbuilt %s\n", buildVersion, buildCommit, buildTime)
}

func main() {
	if status, handled := runOfflineCommand(os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(status)
	}
	if err := run(os.Args[1:]); errors.Is(err, errRestartRequested) {
		os.Exit(restartExitStatus)
	} else if errors.Is(err, errUsage) {
		os.Exit(2)
	} else if err != nil {
		// run reports its own failures; the exit status lets service
		// managers such as systemd detect and restart a failed start.
		os.Exit(1)
	}
}

// restartExitStatus (EX_TEMPFAIL) asks the service manager to start Veksel
// again; deploy/systemd/veksel.service lists it in RestartForceExitStatus.
const restartExitStatus = 75

var errRestartRequested = errors.New("restart requested")

// run starts the server and blocks until it shuts down. Startup failures are
// logged and returned so main can exit non-zero.
func run(args []string) error {
	dataDir, exit, err := parseFlags(args)
	if exit || err != nil {
		return err
	}
	s := &server{mux: http.NewServeMux()}
	defer func() { s.cleanup.run(!s.drained) }()

	started := time.Now()
	for _, phase := range s.startupPhases(dataDir) {
		phaseStarted := time.Now()
		if err := phase.run(); err != nil {
			return err
		}
		// Slow phases are named so operators can see where startup goes.
		if took := time.Since(phaseStarted); took >= slowStartupPhase {
			log.Info("startup phase finished", "phase", phase.name, "duration", took.Round(time.Millisecond))
		}
	}
	log.Info("startup complete", "duration", time.Since(started).Round(time.Millisecond))

	exitErr := s.waitForStop()
	s.shutdown()
	return exitErr
}

// startupPhases lists the startup phases in dependency order: stores before
// services, services before HTTP, IMAP before SMTP delivery, and the durable
// queue before anything that submits into it.
func (s *server) startupPhases(dataDir string) []startupPhase {
	return []startupPhase{
		{"open runtime", func() error { return s.openRuntime(dataDir) }},
		{"open accounts", s.openAccounts},
		{"backup schedule", s.startBackupSchedule},
		{"directory", s.startDirectory},
		{"system services", s.startSystemServices},
		{"protocol settings", s.registerProtocolSettings},
		{"folder space", s.buildFolderSpace},
		{"managesieve", s.startManageSieve},
		{"health", s.buildHealth},
		{"build http", s.buildHTTP},
		{"bind http listeners", s.bindHTTPListeners},
		{"signals", s.watchSignals},
		{"start http", s.startHTTP},
		{"dns server", s.startDNSServer},
		{"imap", s.startIMAP},
		{"pop3", s.startPOP3},
		{"mail services", s.buildMailServices},
		{"smtp", s.startSMTP},
		{"health monitoring", s.startHealthMonitoring},
	}
}

// slowStartupPhase is the duration from which a startup phase is logged.
const slowStartupPhase = time.Second

// logSlowStartupStep logs a step inside a startup phase that took at least
// slowStartupPhase since started.
func logSlowStartupStep(step string, started time.Time, attrs ...any) {
	if took := time.Since(started); took >= slowStartupPhase {
		log.Info("startup step finished", append([]any{"step", step, "duration", took.Round(time.Millisecond)}, attrs...)...)
	}
}

// startupPhase is one named step of server startup.
type startupPhase struct {
	name string
	run  func() error
}

// parseFlags parses the command line. exit reports that run should return
// without starting the server, as after -help or -version.
func parseFlags(args []string) (dataDir string, exit bool, err error) {
	return parseFlagsTo(args, os.Stdout, os.Stderr)
}

// errUsage reports a command line Veksel does not understand; main exits 2.
var errUsage = errors.New("usage")

const defaultDataDir = "./data"

// parseFlagsTo parses the server command line. It refuses words it does not
// know, so a mistyped subcommand never starts a server, and it only uses an
// installation that exists: the default ./data must hold a config.toml, an
// explicit --data-dir must exist (an empty directory is a first start), and
// --init creates a missing one.
func parseFlagsTo(args []string, stdout, stderr io.Writer) (dataDir string, exit bool, err error) {
	flags := flag.NewFlagSet("veksel", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDirFlag := flags.String("data-dir", defaultDataDir, "directory containing Veksel data and config.toml")
	initFlag := flags.Bool("init", false, "create the data directory if it does not exist (first installation)")
	showVersion := flags.Bool("version", false, "print build version and exit")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: veksel [--data-dir DIR] [--init]")
		_, _ = fmt.Fprintln(stderr, "       veksel reset-password|backup|restore|backup-verify [options] (see veksel COMMAND --help)")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", true, nil
		}
		return "", true, errUsage
	}
	if *showVersion {
		writeBuildVersion(stdout)
		return "", true, nil
	}
	if flags.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "veksel: unknown command %q\n", flags.Arg(0))
		flags.Usage()
		return "", true, errUsage
	}
	dataDir = *dataDirFlag
	explicit := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "data-dir" {
			explicit = true
		}
	})
	info, statErr := os.Stat(dataDir)
	switch {
	case statErr == nil && !info.IsDir():
		_, _ = fmt.Fprintf(stderr, "veksel: %s is not a directory\n", dataDir)
		return "", true, errUsage
	case statErr != nil && !os.IsNotExist(statErr):
		_, _ = fmt.Fprintf(stderr, "veksel: %v\n", statErr)
		return "", true, statErr
	case statErr != nil && !*initFlag:
		_, _ = fmt.Fprintf(stderr, "veksel: no data directory at %s; pass --data-dir with an existing directory, or --init to create a new installation there\n", dataDir)
		return "", true, errUsage
	case statErr != nil:
		if err := os.MkdirAll(dataDir, 0o750); err != nil {
			_, _ = fmt.Fprintf(stderr, "veksel: create %s: %v\n", dataDir, err)
			return "", true, err
		}
	case !explicit && !*initFlag:
		if _, err := os.Stat(filepath.Join(dataDir, "config.toml")); err != nil {
			_, _ = fmt.Fprintf(stderr, "veksel: %s holds no Veksel installation; pass --data-dir, or --init to start a new one there\n", dataDir)
			return "", true, errUsage
		}
	}
	return dataDir, false, nil
}
