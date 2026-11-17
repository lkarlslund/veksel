package queue

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

const (
	crashHelperFlag = "VEKSEL_QUEUE_CRASH_HELPER"
	crashStorePath  = "VEKSEL_QUEUE_CRASH_STORE"
	crashEngine     = "VEKSEL_QUEUE_CRASH_ENGINE"
)

func TestPersistentQueueRecoversAfterProcessExitDuringDelivery(t *testing.T) {
	if os.Getenv(crashHelperFlag) == "1" {
		runQueueCrashHelper()
		return
	}
	for _, engine := range []store.Backend{store.BackendPebble, store.BackendBadger} {
		t.Run(string(engine), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "queue")
			command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPersistentQueueRecoversAfterProcessExitDuringDelivery$")
			command.Env = append(os.Environ(), crashHelperFlag+"=1", crashStorePath+"="+path, crashEngine+"="+string(engine))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("crash helper: %v\n%s", err, output)
			}

			backend := openCrashStore(t, engine, path)
			defer func() { _ = backend.Close() }()
			q, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			defer q.Close()
			message := q.Get("crash-claim")
			if message == nil || message.Status != StatusPending || message.AttemptID != "" || message.NextRetry.After(time.Now().UTC()) {
				t.Fatalf("recovered message = %#v", message)
			}
		})
	}
}

func runQueueCrashHelper() {
	engine := store.Backend(os.Getenv(crashEngine))
	backend, err := openCrashStoreRaw(engine, os.Getenv(crashStorePath))
	if err != nil {
		os.Exit(2)
	}
	if err := backend.CreateNamespace(context.Background(), model.NSQueue); err != nil {
		os.Exit(3)
	}
	q, err := NewPersistent(context.Background(), backend, &Config{
		Workers:       1,
		ProcessPeriod: time.Hour,
		Delivery: func(context.Context, *Message) error {
			// Deliberately bypass every defer and Close call after the durable
			// processing claim, matching an abrupt process or machine failure.
			os.Exit(0)
			return nil
		},
	})
	if err != nil {
		os.Exit(4)
	}
	if err := q.Enqueue(&Message{ID: "crash-claim", Recipient: "alice@example.test", Content: []byte("durable")}); err != nil {
		os.Exit(5)
	}
	select {}
}

func openCrashStore(t *testing.T, engine store.Backend, path string) store.Store {
	t.Helper()
	backend, err := openCrashStoreRaw(engine, path)
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

func openCrashStoreRaw(engine store.Backend, path string) (store.Store, error) {
	switch engine {
	case store.BackendPebble:
		return pebblestore.New(path)
	case store.BackendBadger:
		return badgerstore.New(path)
	default:
		return nil, store.ErrNotFound
	}
}
