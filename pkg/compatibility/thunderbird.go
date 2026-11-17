package compatibility

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var thunderbirdVersionPattern = regexp.MustCompile(`(?i)Thunderbird\s+([^\s]+)`)

type ThunderbirdProbeOptions struct {
	Binary          string
	ExpectedVersion string
	Timeout         time.Duration
}

type ThunderbirdProbeResult struct {
	Version    string   `json:"version"`
	Commands   []string `json:"commands"`
	DurationMS int64    `json:"duration_ms"`
}

// RunThunderbirdProbe starts an isolated display, profile, and Veksel account.
// It records only IMAP command names; credentials and message content never
// enter retained compatibility evidence.
func RunThunderbirdProbe(ctx context.Context, options ThunderbirdProbeOptions) (ThunderbirdProbeResult, error) {
	started := time.Now()
	if strings.TrimSpace(options.Binary) == "" {
		return ThunderbirdProbeResult{}, errors.New("Thunderbird binary is required")
	}
	if options.Timeout <= 0 {
		options.Timeout = 90 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	version, err := thunderbirdVersion(probeCtx, options.Binary)
	if err != nil {
		return ThunderbirdProbeResult{}, err
	}
	if options.ExpectedVersion != "" && version != options.ExpectedVersion {
		return ThunderbirdProbeResult{}, fmt.Errorf("Thunderbird version %q, want %q", version, options.ExpectedVersion)
	}

	directory, err := os.MkdirTemp("", "veksel-thunderbird-probe-")
	if err != nil {
		return ThunderbirdProbeResult{}, err
	}
	defer os.RemoveAll(directory)
	fixture, err := StartIMAPFixture(probeCtx, filepath.Join(directory, "store"))
	if err != nil {
		return ThunderbirdProbeResult{}, err
	}
	defer fixture.Close()

	profile := filepath.Join(directory, "profile")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return ThunderbirdProbeResult{}, err
	}
	host, portText, err := netSplitHostPort(fixture.Address)
	if err != nil {
		return ThunderbirdProbeResult{}, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return ThunderbirdProbeResult{}, err
	}
	if err := writeThunderbirdProfile(profile, host, port, fixture.Username); err != nil {
		return ThunderbirdProbeResult{}, err
	}

	display, xvfb, err := startXvfb(probeCtx)
	if err != nil {
		return ThunderbirdProbeResult{}, err
	}
	defer stopProcess(xvfb)
	environment := append(os.Environ(), "DISPLAY="+display)
	client := exec.CommandContext(probeCtx, options.Binary, "--no-remote", "--profile", profile)
	client.Env = environment
	clientOutput := &lockedBuffer{}
	client.Stdout = clientOutput
	client.Stderr = clientOutput
	if err := client.Start(); err != nil {
		return ThunderbirdProbeResult{}, fmt.Errorf("start Thunderbird: %w", err)
	}
	defer stopThunderbird(client, environment)

	required := []string{"CAPABILITY", "AUTHENTICATE", "LIST", "SELECT", "UID FETCH"}
	waitDone := make(chan struct{})
	var commands []string
	var waitErr error
	go func() {
		defer close(waitDone)
		commands, waitErr = fixture.WaitFor(probeCtx, required)
	}()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	passwordEntered := false
	for {
		select {
		case <-waitDone:
			if waitErr != nil {
				return ThunderbirdProbeResult{}, fmt.Errorf("Thunderbird workflow: %w; client output: %s", waitErr, strings.TrimSpace(clientOutput.String()))
			}
			return ThunderbirdProbeResult{Version: version, Commands: commands, DurationMS: time.Since(started).Milliseconds()}, nil
		case <-ticker.C:
			if !passwordEntered {
				passwordEntered = enterThunderbirdPassword(probeCtx, environment, fixture.Password)
			}
		case <-probeCtx.Done():
			<-waitDone
			return ThunderbirdProbeResult{}, fmt.Errorf("Thunderbird probe: %w; observed: %s; client output: %s", probeCtx.Err(), strings.Join(commands, ", "), strings.TrimSpace(clientOutput.String()))
		}
	}
}

func thunderbirdVersion(ctx context.Context, binary string) (string, error) {
	output, err := exec.CommandContext(ctx, binary, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read Thunderbird version: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	match := thunderbirdVersionPattern.FindStringSubmatch(string(output))
	if len(match) != 2 {
		return "", fmt.Errorf("could not parse Thunderbird version from %q", strings.TrimSpace(string(output)))
	}
	return match[1], nil
}

func writeThunderbirdProfile(profile, host string, port int, username string) error {
	prefs := fmt.Sprintf(`user_pref("app.update.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("mail.account.account1.identities", "id1");
user_pref("mail.account.account1.server", "server1");
user_pref("mail.accountmanager.accounts", "account1");
user_pref("mail.accountmanager.defaultaccount", "account1");
user_pref("mail.accountmanager.localfoldersserver", "server2");
user_pref("mail.biff.show_alert", false);
user_pref("mail.identity.id1.fullName", "Compatibility Fixture");
user_pref("mail.identity.id1.smtpServer", "smtp1");
user_pref("mail.identity.id1.useremail", "compat@example.test");
user_pref("mail.server.server1.authMethod", 3);
user_pref("mail.server.server1.check_new_mail", true);
user_pref("mail.server.server1.download_on_biff", true);
user_pref("mail.server.server1.hostname", %q);
user_pref("mail.server.server1.login_at_startup", true);
user_pref("mail.server.server1.name", "compat@example.test");
user_pref("mail.server.server1.port", %d);
user_pref("mail.server.server1.socketType", 0);
user_pref("mail.server.server1.type", "imap");
user_pref("mail.server.server1.userName", %q);
user_pref("mail.server.server2.hostname", "Local Folders");
user_pref("mail.server.server2.name", "Local Folders");
user_pref("mail.server.server2.type", "none");
user_pref("mail.server.server2.userName", "nobody");
user_pref("mail.shell.checkDefaultClient", false);
user_pref("mail.smtp.defaultserver", "smtp1");
user_pref("mail.smtpserver.smtp1.hostname", %q);
user_pref("mail.smtpserver.smtp1.port", %d);
user_pref("mail.smtpserver.smtp1.username", %q);
user_pref("mail.smtpservers", "smtp1");
user_pref("mail.startup.enabledMailCheckOnce", true);
user_pref("mailnews.start_page.enabled", false);
`, host, port, username, host, port, username)
	return os.WriteFile(filepath.Join(profile, "prefs.js"), []byte(prefs), 0o600)
}

func startXvfb(ctx context.Context) (string, *exec.Cmd, error) {
	path, err := exec.LookPath("Xvfb")
	if err != nil {
		return "", nil, errors.New("Xvfb is required for the Thunderbird probe")
	}
	for number := 100; number < 200; number++ {
		socket := filepath.Join("/tmp/.X11-unix", "X"+strconv.Itoa(number))
		if _, err := os.Stat(socket); err == nil {
			continue
		}
		display := ":" + strconv.Itoa(number)
		command := exec.CommandContext(ctx, path, display, "-screen", "0", "1280x800x24", "-nolisten", "tcp")
		if err := command.Start(); err != nil {
			continue
		}
		for range 50 {
			if _, err := os.Stat(socket); err == nil {
				return display, command, nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		stopProcess(command)
	}
	return "", nil, errors.New("could not start an isolated X display")
}

func enterThunderbirdPassword(ctx context.Context, environment []string, password string) bool {
	path, err := exec.LookPath("xdotool")
	if err != nil {
		return false
	}
	for _, title := range []string{"Password Required", "Authentication Required", "Enter your password"} {
		search := exec.CommandContext(ctx, path, "search", "--onlyvisible", "--name", title)
		search.Env = environment
		output, searchErr := search.Output()
		windows := strings.Fields(string(output))
		if searchErr != nil || len(windows) == 0 {
			continue
		}
		window := windows[len(windows)-1]
		for _, arguments := range [][]string{
			{"windowfocus", "--sync", window},
			{"type", "--window", window, "--clearmodifiers", "--delay", "5", password},
			{"mousemove", "--window", window, "385", "143", "click", "1"},
		} {
			command := exec.CommandContext(ctx, path, arguments...)
			command.Env = environment
			if command.Run() != nil {
				return false
			}
			if arguments[0] == "type" {
				time.Sleep(200 * time.Millisecond)
			}
		}
		return true
	}
	return false
}

func stopProcess(command *exec.Cmd) {
	if command == nil || command.Process == nil || command.ProcessState != nil {
		return
	}
	_ = command.Process.Kill()
	_ = command.Wait()
}

func stopThunderbird(command *exec.Cmd, environment []string) {
	if command == nil || command.Process == nil || command.ProcessState != nil {
		return
	}
	if path, err := exec.LookPath("xdotool"); err == nil {
		closeCommand := exec.Command(path, "search", "--onlyvisible", "--class", "thunderbird", "windowfocus", "--sync", "key", "--clearmodifiers", "ctrl+q")
		closeCommand.Env = environment
		_ = closeCommand.Run()
	}
	done := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-done
	}
}

type lockedBuffer struct {
	mu   sync.Mutex
	data strings.Builder
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

// Kept behind a helper so profile generation can be tested without opening a
// network connection and malformed fixture addresses get a precise error.
func netSplitHostPort(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", fmt.Errorf("split fixture address: %w", err)
	}
	return host, port, nil
}
