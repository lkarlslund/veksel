package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFlagsRefusesUnknownWordsAndMissingInstallations(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing")
	if err := os.Mkdir(existing, 0o750); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing")
	for name, test := range map[string]struct {
		args    []string
		wantDir string
		wantErr bool
		stderr  string
	}{
		"subcommand typo":      {args: []string{"--data-dir", existing, "account", "--help"}, wantErr: true, stderr: `unknown command "account"`},
		"bare unknown word":    {args: []string{"accounts"}, wantErr: true, stderr: "unknown command"},
		"explicit empty dir":   {args: []string{"--data-dir", existing}, wantDir: existing},
		"explicit missing dir": {args: []string{"--data-dir", missing}, wantErr: true, stderr: "--init"},
		"init creates":         {args: []string{"--data-dir", filepath.Join(root, "new"), "--init"}, wantDir: filepath.Join(root, "new")},
	} {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			dir, exit, err := parseFlagsTo(test.args, &bytes.Buffer{}, &stderr)
			if test.wantErr {
				if err == nil || !exit {
					t.Fatalf("accepted %v", test.args)
				}
				if !strings.Contains(stderr.String(), test.stderr) {
					t.Fatalf("stderr %q lacks %q", stderr.String(), test.stderr)
				}
				return
			}
			if err != nil || exit || dir != test.wantDir {
				t.Fatalf("dir=%q exit=%v err=%v stderr=%s", dir, exit, err, stderr.String())
			}
			if _, statErr := os.Stat(dir); statErr != nil {
				t.Fatal(statErr)
			}
		})
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a missing data directory was created without --init")
	}
}

func TestParseFlagsDefaultDirNeedsAnInstallation(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, _, err := parseFlagsTo(nil, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, errUsage) {
		t.Fatalf("started without ./data: %v", err)
	}
	if err := os.MkdirAll("data", 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseFlagsTo(nil, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, errUsage) {
		t.Fatalf("started with an empty ./data: %v", err)
	}
	if err := os.WriteFile(filepath.Join("data", "config.toml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if dir, _, err := parseFlagsTo(nil, &bytes.Buffer{}, &bytes.Buffer{}); err != nil || dir != defaultDataDir {
		t.Fatalf("dir=%q err=%v", dir, err)
	}
}
