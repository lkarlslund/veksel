package compatibility

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/imap"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

const (
	FixtureUsername = "compat"
	FixturePassword = "compatpassword"
)

var knownIMAPCommands = map[string]bool{
	"CAPABILITY": true, "LOGIN": true, "AUTHENTICATE": true, "ID": true,
	"NAMESPACE": true, "LIST": true, "LSUB": true, "STATUS": true,
	"SELECT": true, "EXAMINE": true, "FETCH": true, "UID FETCH": true,
	"SEARCH": true, "UID SEARCH": true, "IDLE": true, "DONE": true,
	"NOOP": true, "LOGOUT": true, "COMPRESS": true,
}

// IMAPFixture runs a disposable Veksel IMAP server with a metadata-only command
// observer. It records command names, never arguments or credentials.
type IMAPFixture struct {
	Address  string
	Username string
	Password string

	cancel     context.CancelFunc
	backend    store.Store
	server     *imap.Server
	serverDone chan struct{}
	mu         sync.Mutex
	commands   []string
	seen       map[string]bool
	changed    chan struct{}
	closeOnce  sync.Once
}

func StartIMAPFixture(ctx context.Context, directory string) (*IMAPFixture, error) {
	backend, err := jsonstore.New(directory)
	if err != nil {
		return nil, fmt.Errorf("open fixture store: %w", err)
	}
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := ts.EnsureNamespace(ctx, namespace); err != nil {
			_ = backend.Close()
			return nil, fmt.Errorf("initialize fixture namespace %s: %w", namespace, err)
		}
	}
	if err := ts.UserStore().Create(ctx, FixtureUsername, "Compatibility Fixture", FixturePassword); err != nil {
		_ = backend.Close()
		return nil, err
	}
	if err := ts.UserStore().AddEmailAddress(ctx, FixtureUsername+"@example.test", FixtureUsername, "example.test", true); err != nil {
		_ = backend.Close()
		return nil, err
	}
	if err := ts.FolderStore().CreateForUser(ctx, FixtureUsername); err != nil {
		_ = backend.Close()
		return nil, err
	}
	message := []byte("Date: Wed, 19 Aug 2026 08:00:00 +0200\r\nFrom: sender@example.test\r\nTo: compat@example.test\r\nSubject: Veksel compatibility fixture\r\nMessage-ID: <fixture@veksel.test>\r\n\r\nFixture body.\r\n")
	if _, err := ts.ItemStore().Append(ctx, model.InboxFolderID(FixtureUsername), message, map[string]string{"Subject": "Veksel compatibility fixture"}); err != nil {
		_ = backend.Close()
		return nil, err
	}

	fixtureCtx, cancel := context.WithCancel(ctx)
	space := service.NewFolderSpace(ts, authz.New(ts))
	fixture := &IMAPFixture{
		Username: FixtureUsername, Password: FixturePassword,
		cancel: cancel, backend: backend, serverDone: make(chan struct{}),
		seen: make(map[string]bool), changed: make(chan struct{}, 1),
	}
	server := imap.New(&imap.Config{
		ServerName: "veksel-compat.test", Version: "compatibility-fixture",
		AuthMechanisms: []string{"PLAIN", "LOGIN"}, SaslIrEnabled: true, TypedStore: ts, FolderSpace: space,
		CommandObserver: fixture.recordCommand,
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if username == FixtureUsername && password == FixturePassword {
				return FixtureUsername, nil
			}
			return "", errors.New("invalid fixture credentials")
		},
	})
	serverListener, err := server.Listen("127.0.0.1:0")
	if err != nil {
		cancel()
		_ = backend.Close()
		return nil, err
	}
	fixture.Address = serverListener.Addr().String()
	fixture.server = server
	go func() {
		defer close(fixture.serverDone)
		server.Accept(fixtureCtx, serverListener)
	}()
	return fixture, nil
}

func (f *IMAPFixture) recordCommand(command string) {
	command = strings.ToUpper(strings.TrimSpace(command))
	if !knownIMAPCommands[command] {
		return
	}
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.seen[command] = true
	f.mu.Unlock()
	select {
	case f.changed <- struct{}{}:
	default:
	}
}

func (f *IMAPFixture) Commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.commands)
}

func (f *IMAPFixture) WaitFor(ctx context.Context, required []string) ([]string, error) {
	for {
		f.mu.Lock()
		missing := make([]string, 0)
		for _, command := range required {
			if !f.seen[strings.ToUpper(command)] {
				missing = append(missing, strings.ToUpper(command))
			}
		}
		commands := slices.Clone(f.commands)
		f.mu.Unlock()
		if len(missing) == 0 {
			return commands, nil
		}
		select {
		case <-ctx.Done():
			return commands, fmt.Errorf("wait for IMAP commands %s: %w", strings.Join(missing, ", "), ctx.Err())
		case <-f.changed:
		}
	}
}

func (f *IMAPFixture) Close() error {
	var err error
	f.closeOnce.Do(func() {
		f.cancel()
		if closeErr := f.server.Close(); closeErr != nil {
			err = closeErr
		}
		<-f.serverDone
		if closeErr := f.backend.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	})
	return err
}
