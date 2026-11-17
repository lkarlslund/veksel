package jmap

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// TestEventSourceWakesOnCommit: over a folder space that notifies commits, a
// change reaches an EventSource promptly although the fallback poll is an
// hour away.
func TestEventSourceWakesOnCommit(t *testing.T) {
	f := buildFixture(t, func(ts *model.TypedStore, _ store.Store, _ service.FolderSpace) service.FolderSpace {
		manager, err := account.NewManager(t.TempDir(), store.BackendPebble)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = manager.Close() })
		for _, login := range []string{"alice", "bob"} {
			user, err := ts.UserStore().Get(t.Context(), login)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.Ensure(t.Context(), user, "", nil); err != nil {
				t.Fatal(err)
			}
		}
		space, err := service.NewAccountFolderSpace(t.Context(), ts, manager, authz.New(ts))
		if err != nil {
			t.Fatal(err)
		}
		return space
	})
	f.cfg.PushInterval = time.Hour
	f.restart(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", f.server.URL+"/jmap/eventsource?types=Email&closeafter=no&ping=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("alice", "password")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	events := make(chan map[string]string, 4)
	go func() {
		reader := bufio.NewReader(response.Body)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				close(events)
				return
			}
			if data, ok := strings.CutPrefix(strings.TrimSpace(line), "data: "); ok {
				var change stateChange
				if json.Unmarshal([]byte(data), &change) == nil {
					events <- change.Changed["alice"]
				}
			}
		}
	}()
	if initial := <-events; initial["Email"] == "" {
		t.Fatalf("initial state = %#v", initial)
	}
	// Let the stream register for alice's account before committing.
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.handler.wakes.mu.Lock()
		watched := len(f.handler.wakes.byAccount["alice"])
		f.handler.wakes.mu.Unlock()
		if watched > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("EventSource never watched alice's account")
		}
		time.Sleep(time.Millisecond)
	}
	inbox := folderByPath(t, f, "alice", "INBOX")
	started := time.Now()
	if _, err := f.space.CreateItem(t.Context(), service.UserAccess("alice", "test"), inbox.ID, service.ItemInput{Data: []byte("Subject: pushed\r\n\r\nbody")}); err != nil {
		t.Fatal(err)
	}
	select {
	case changed := <-events:
		if changed["Email"] == "" {
			t.Fatalf("push = %#v", changed)
		}
		if elapsed := time.Since(started); elapsed > pushSettle+time.Second {
			t.Fatalf("push took %v", elapsed)
		}
		t.Logf("commit to StateChange: %v", time.Since(started))
	case <-time.After(5 * time.Second):
		t.Fatal("no StateChange after a commit")
	}
}
