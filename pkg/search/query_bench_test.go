package search

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// BenchmarkContactQuery measures the contact workspace list request: one
// page of 100 summaries sorted by name from a 370-contact address book in
// which every third contact carries a photo.
func BenchmarkContactQuery(b *testing.B) {
	ctx := b.Context()
	backend, err := pebblestore.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = backend.Close() })
	system := model.NewTypedStore(backend, store.BackendPebble)
	for _, namespace := range model.Namespaces() {
		if err := system.EnsureNamespace(ctx, namespace); err != nil {
			b.Fatal(err)
		}
	}
	if err := system.UserStore().Create(ctx, "alice", "Alice", "password123"); err != nil {
		b.Fatal(err)
	}
	if err := system.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		b.Fatal(err)
	}
	accounts, err := account.NewManager(b.TempDir(), store.BackendPebble)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = accounts.Close() })
	user, _ := system.UserStore().Get(ctx, "alice")
	if _, _, err := accounts.Ensure(ctx, user, "alice@example.test", nil); err != nil {
		b.Fatal(err)
	}
	engine := authz.New(system)
	space, err := service.NewAccountFolderSpace(ctx, system, accounts, engine)
	if err != nil {
		b.Fatal(err)
	}
	access := service.UserAccess("alice", "bench")
	folder, err := space.CreateFolder(ctx, access, "Clients", model.FolderTypeContacts, "")
	if err != nil {
		b.Fatal(err)
	}
	photo := "PHOTO;ENCODING=b;TYPE=JPEG:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("jpeg-bytes", 2000))) + "\r\n"
	inputs := make([]service.ItemInput, 0, 370)
	for n := range 370 {
		card := fmt.Sprintf("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:contact-%d\r\nFN:Person %03d Example\r\nN:Example;Person %03d;;;\r\nORG:Company %d\r\nTITLE:Engineer\r\nEMAIL;TYPE=work:person%d@example.test\r\nEMAIL;TYPE=home:p%d@home.example\r\nTEL;TYPE=cell:+45 %08d\r\nADR;TYPE=work:;;Street %d;City;;%04d;Denmark\r\nNOTE:Met at the conference\\, follow up on the proposal.\r\n",
			n, n, n, n%25, n, n, 20000000+n, n, 1000+n)
		if n%3 == 0 {
			card += photo
		}
		inputs = append(inputs, service.ItemInput{Name: fmt.Sprintf("contact-%d.vcf", n), Data: []byte(card + "END:VCARD\r\n")})
	}
	if _, err := space.CreateItems(ctx, access, folder.ID, inputs); err != nil {
		b.Fatal(err)
	}
	manager, err := New(ctx, accounts, space, engine, Config{Enabled: true, Workers: 1, BatchSize: 100, IdleClose: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = manager.Close() })
	waitReady(b, manager, access, "alice")
	query := service.SearchQuery{AccountID: "alice", FolderIDs: []string{folder.ID}, Types: []model.FolderType{model.FolderTypeContacts}, Sort: "contact_name", Limit: 100}
	waitHits(b, manager, access, query, 100)
	for _, scoped := range []bool{false, true} {
		b.Run(map[bool]string{false: "unscoped", true: "request-scoped"}[scoped], func(b *testing.B) {
			for range b.N {
				requestCtx := ctx
				if scoped {
					requestCtx = authz.WithRequestScope(ctx)
				}
				page, err := manager.Search(requestCtx, access, query)
				if err != nil {
					b.Fatal(err)
				}
				if len(page.Hits) != 100 || page.Total != 370 {
					b.Fatalf("hits=%d total=%d", len(page.Hits), page.Total)
				}
			}
		})
	}
}
