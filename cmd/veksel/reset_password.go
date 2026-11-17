package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
)

// runResetPassword is the operator break-glass path for a lost password or
// lost second factors. It needs exclusive store access, so the server must be
// stopped first.
func runResetPassword(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data-dir", "./data", "directory containing Veksel data and config.toml")
	clearTwoFactor := flags.Bool("clear-2fa", false, "also remove USER's two-factor sign-in factors and recovery codes")
	keepPassword := flags.Bool("keep-password", false, "leave the password unchanged (use with --clear-2fa)")
	passwordStdin := flags.Bool("password-stdin", false, "read the new password from the first line of standard input instead of generating one")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: veksel reset-password [--data-dir DIR] [--clear-2fa [--keep-password]] USER")
		fmt.Fprintln(stderr, "Sets a new random password for USER and prints it, or the password read with --password-stdin. Stop the server first.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfgService, err := config.Open(*dataDir)
	if err != nil {
		return fmt.Errorf("open configuration: %w", err)
	}
	cfg := cfgService.Current().Config
	backend, err := cfg.OpenStore()
	if err != nil {
		return fmt.Errorf("open store (is the server still running?): %w", err)
	}
	defer backend.Close()
	ts := model.NewTypedStore(backend, cfg.StoreBackend)
	ctx := context.Background()
	if err := model.InitializeSystemStore(ctx, ts); err != nil {
		return err
	}
	users := model.NewUserStore(ts)

	if flags.NArg() != 1 {
		flags.Usage()
		list, err := users.List(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintln(stderr, "users:")
		for _, user := range list {
			fmt.Fprintf(stderr, "  %s\n", user.ID)
		}
		return errors.New("exactly one USER is required")
	}
	userID := flags.Arg(0)
	if *keepPassword && !*clearTwoFactor {
		return errors.New("--keep-password requires --clear-2fa")
	}
	if *keepPassword && *passwordStdin {
		return errors.New("--keep-password and --password-stdin cannot be combined")
	}
	password := rand.Text()
	if *passwordStdin {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read password: %w", err)
		}
		if password = strings.TrimRight(line, "\r\n"); password == "" {
			return errors.New("the password read from standard input is empty")
		}
	}
	if *clearTwoFactor {
		if _, err := users.Get(ctx, userID); err != nil {
			return fmt.Errorf("user %q: %w", userID, err)
		}
		existed, err := model.NewSecondFactorStore(ts).Delete(ctx, userID)
		if err != nil {
			return fmt.Errorf("clear two-factor sign-in: %w", err)
		}
		audit.New(ts).Log("cli", "account.two_factor.reset", userID, map[string]string{"had_factors": fmt.Sprint(existed), "source": "reset-password"})
		fmt.Fprintf(stdout, "two-factor sign-in cleared for %s\n", userID)
		if *keepPassword {
			return nil
		}
	}
	token, err := users.GeneratePasswordResetToken(ctx, userID)
	if err != nil {
		return fmt.Errorf("user %q: %w", userID, err)
	}
	if err := users.CompletePasswordReset(ctx, token, password); err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	if *passwordStdin {
		fmt.Fprintf(stdout, "password for %s updated\n", userID)
		return nil
	}
	fmt.Fprintf(stdout, "new password for %s: %s\n", userID, password)
	return nil
}
