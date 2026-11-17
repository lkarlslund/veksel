package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestSieveRepositoryNamedScriptsActiveInvariantAndIsolation(t *testing.T) {
	_, ts, _ := testMailService(t)
	repo := NewSieveRepository(NewFolderSpace(ts, authz.New(ts)))
	ctx := t.Context()

	if err := repo.Put(ctx, "alice", "personal", `require ["fileinto"]; fileinto "Archive";`); err != nil {
		t.Fatal(err)
	}
	if err := repo.Put(ctx, "alice", "vacation", `keep;`); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetActive(ctx, "alice", "personal"); err != nil {
		t.Fatal(err)
	}
	if script, active, err := repo.Active(ctx, "alice"); err != nil || !active || !strings.Contains(script, "fileinto") {
		t.Fatalf("Active() = (%q, %t, %v)", script, active, err)
	}
	if _, active, err := repo.Active(ctx, "bob"); err != nil || active {
		t.Fatalf("bob Active() = (_, %t, %v)", active, err)
	}
	if err := repo.Delete(ctx, "alice", "personal"); !errors.Is(err, ErrActive) {
		t.Fatalf("delete active error = %v", err)
	}
	if err := repo.Rename(ctx, "alice", "personal", "primary"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(ctx, "alice", "personal"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old name error = %v", err)
	}
	infos, err := repo.List(ctx, "alice")
	if err != nil || len(infos) != 2 || !infos[0].Active || infos[0].Name != "primary" {
		t.Fatalf("List() = (%+v, %v)", infos, err)
	}
	if err := repo.SetActive(ctx, "alice", "vacation"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Delete(ctx, "alice", "primary"); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetActive(ctx, "alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, active, err := repo.Active(ctx, "alice"); err != nil || active {
		t.Fatalf("disabled Active() = (_, %t, %v)", active, err)
	}
}

func TestSieveRepositoryRejectsInvalidInputWithoutReplacingScript(t *testing.T) {
	_, ts, _ := testMailService(t)
	repo := NewSieveRepository(NewFolderSpace(ts, authz.New(ts)))
	ctx := t.Context()
	if err := repo.Put(ctx, "alice", "safe", `keep;`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, script string }{
		{"", `keep;`}, {"bad\nname", `keep;`}, {"safe", `if {`}, {strings.Repeat("x", 513), `keep;`},
		{"safe", `require "imap4flags"; keep;`}, {"safe", `fileinto "A";`},
	} {
		if err := repo.Put(ctx, "alice", tc.name, tc.script); err == nil {
			t.Fatalf("Put(%q, %q) succeeded", tc.name, tc.script)
		}
	}
	if script, err := repo.Get(ctx, "alice", "safe"); err != nil || script != `keep;` {
		t.Fatalf("safe script = (%q, %v)", script, err)
	}
}
