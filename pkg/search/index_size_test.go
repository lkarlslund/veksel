package search

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/lkarlslund/veksel/pkg/model"
)

// sizeCorpus is a deterministic synthetic mailbox: plain, HTML, and
// multipart/alternative bodies with realistic transport headers (Received
// chains, DKIM and ARC signatures), a share with text and binary
// attachments, plus a few contacts and events. Words follow a Zipf-like
// distribution over a fixed vocabulary so the term dictionary grows the way a
// real mailbox does.
type sizeCorpus struct {
	rng   *rand.Rand
	vocab []string
	zipf  *rand.Zipf
}

func newSizeCorpus() *sizeCorpus {
	rng := rand.New(rand.NewPCG(7, 11))
	syllables := []string{"ka", "lo", "mi", "ren", "ta", "vos", "el", "ung", "pri", "dar", "se", "no", "qua", "tor", "bel", "fi", "ga", "hum", "ix", "jo"}
	vocab := make([]string, 6000)
	for index := range vocab {
		var word strings.Builder
		for range 2 + rng.IntN(3) {
			word.WriteString(syllables[rng.IntN(len(syllables))])
		}
		vocab[index] = word.String()
	}
	return &sizeCorpus{rng: rng, vocab: vocab, zipf: rand.NewZipf(rng, 1.1, 2, uint64(len(vocab)-1))}
}

func (c *sizeCorpus) words(count int) string {
	var text strings.Builder
	for index := range count {
		if index > 0 {
			if index%14 == 0 {
				text.WriteString(".\n")
			} else {
				text.WriteByte(' ')
			}
		}
		text.WriteString(c.vocab[c.zipf.Uint64()])
	}
	return text.String()
}

func (c *sizeCorpus) blob(size int) string {
	raw := make([]byte, size)
	for index := range raw {
		raw[index] = byte(c.rng.Uint32())
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func wrap76(text string) string {
	var lines []string
	for len(text) > 76 {
		lines = append(lines, text[:76])
		text = text[76:]
	}
	return strings.Join(append(lines, text), "\r\n")
}

func (c *sizeCorpus) message(n int) []byte {
	sender := fmt.Sprintf("%s.%s@%s.example", c.vocab[c.rng.IntN(300)], c.vocab[c.rng.IntN(300)], c.vocab[c.rng.IntN(40)])
	headers := []string{
		fmt.Sprintf("Received: from mx%d.%s.example (mx%d.%s.example [192.0.2.%d]) by mail.veksel.test with ESMTPS id %s; Mon, 5 Oct 2026 10:%02d:00 +0000", n%7, c.vocab[n%40], n%7, c.vocab[n%40], n%250, c.blob(9), n%60),
		fmt.Sprintf("Received: from [10.0.%d.%d] by mx.%s.example with HTTP; Mon, 5 Oct 2026 10:%02d:00 +0000", n%200, n%250, c.vocab[n%40], n%60),
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + c.vocab[n%40] + ".example; s=sel" + fmt.Sprint(n%3) + "; h=from:to:subject:date:message-id; bh=" + c.blob(32) + "; b=" + c.blob(256),
		"ARC-Seal: i=1; a=rsa-sha256; t=1760000000; cv=none; d=relay.example; s=arc; b=" + c.blob(256),
		"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=relay.example; s=arc; h=from:to:subject; bh=" + c.blob(32) + "; b=" + c.blob(256),
		"Authentication-Results: mail.veksel.test; dkim=pass header.d=" + c.vocab[n%40] + ".example; spf=pass smtp.mailfrom=" + sender,
		"From: " + c.vocab[c.rng.IntN(300)] + " <" + sender + ">",
		fmt.Sprintf("To: alice@veksel.test, %s@%s.example", c.vocab[c.rng.IntN(500)], c.vocab[c.rng.IntN(40)]),
		"Subject: " + c.words(4+c.rng.IntN(6)),
		fmt.Sprintf("Message-ID: <%s@%s.example>", c.blob(18), c.vocab[n%40]),
		fmt.Sprintf("Date: Mon, 5 Oct 2026 10:%02d:00 +0000", n%60),
		"MIME-Version: 1.0",
	}
	body := c.words(60 + c.rng.IntN(500))
	var parts []string
	switch {
	case n%10 == 0:
		// A share: a short note, a CSV with extractable text, and a PDF whose
		// bytes must never reach the index.
		parts = []string{
			"Content-Type: multipart/mixed; boundary=mixed", "", "--mixed",
			"Content-Type: text/plain; charset=utf-8", "", body, "--mixed",
			"Content-Type: text/csv; name=figures.csv", "Content-Disposition: attachment; filename=figures.csv",
			"Content-Transfer-Encoding: base64", "", wrap76(base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(c.words(800), " ", ",")))),
			"--mixed", "Content-Type: application/pdf; name=report.pdf", "Content-Disposition: attachment; filename=report.pdf",
			"Content-Transfer-Encoding: base64", "", wrap76(c.blob(48 << 10)), "--mixed--", "",
		}
	case n%3 == 0:
		html := "<html><body><p>" + strings.ReplaceAll(body, "\n", "</p><p>") + "</p></body></html>"
		parts = []string{
			"Content-Type: multipart/alternative; boundary=alt", "", "--alt",
			"Content-Type: text/plain; charset=utf-8", "", body, "--alt",
			"Content-Type: text/html; charset=utf-8", "", html, "--alt--", "",
		}
	default:
		parts = []string{"Content-Type: text/plain; charset=utf-8", "", body}
	}
	return []byte(strings.Join(append(headers, parts...), "\r\n"))
}

func indexBytes(t testing.TB, root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			if info, infoErr := entry.Info(); infoErr == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// TestIndexSizeOnRepresentativeCorpus indexes the synthetic mailbox with the
// production mapping and extraction and reports the index bytes against the
// raw mail bytes. The bound guards against regressions to the v9 mapping,
// which built an index about the size of the mail itself.
func TestIndexSizeOnRepresentativeCorpus(t *testing.T) {
	corpus := newSizeCorpus()
	root := filepath.Join(t.TempDir(), "index")
	idx, err := bleve.New(root, indexMapping())
	if err != nil {
		t.Fatal(err)
	}
	mailFolder := model.Folder{ID: "alice:INBOX", Name: "INBOX", Type: model.FolderTypeMail, UserID: "alice"}
	contacts := model.Folder{ID: "alice:Contacts", Name: "Contacts", Type: model.FolderTypeContacts, UserID: "alice"}
	calendar := model.Folder{ID: "alice:Calendar", Name: "Calendar", Type: model.FolderTypeCalendar, UserID: "alice"}
	var rawBytes, textBytes int64
	batch := idx.NewBatch()
	add := func(folder model.Folder, item model.Item) {
		item.FolderID, item.Size = folder.ID, int64(len(item.Data))
		rawBytes += int64(len(item.Data))
		doc := extract(folder, item, (Config{}).normalized().MaxExtractedBytes)
		textBytes += int64(len(documentText(doc)))
		if err := batch.Index(item.ID, doc); err != nil {
			t.Fatal(err)
		}
		if batch.Size() >= 256 {
			if err := idx.Batch(batch); err != nil {
				t.Fatal(err)
			}
			batch = idx.NewBatch()
		}
	}
	date := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for n := range 600 {
		add(mailFolder, model.Item{ID: fmt.Sprintf("m%04d", n), Data: corpus.message(n), InternalDate: date.Add(time.Duration(n) * time.Minute),
			Flags: []string{model.FlagSeen}, Headers: map[string]string{"X-Veksel-Command-ID": corpus.blob(12)}})
	}
	for n := range 40 {
		card := fmt.Sprintf("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:c%d\r\nFN:%s %s\r\nORG:%s\r\nEMAIL:%s@%s.example\r\nTEL:+45 %08d\r\nNOTE:%s\r\nEND:VCARD\r\n",
			n, corpus.vocab[n], corpus.vocab[n+50], corpus.vocab[n+100], corpus.vocab[n], corpus.vocab[n%40], 20000000+n, corpus.words(20))
		add(contacts, model.Item{ID: fmt.Sprintf("c%04d", n), Data: []byte(card), InternalDate: date})
	}
	for n := range 40 {
		event := fmt.Sprintf("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:e%d\r\nSUMMARY:%s\r\nLOCATION:%s\r\nDESCRIPTION:%s\r\nDTSTART:20261005T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
			n, corpus.words(4), corpus.words(2), corpus.words(40))
		add(calendar, model.Item{ID: fmt.Sprintf("e%04d", n), Data: []byte(event), InternalDate: date, Headers: map[string]string{"SUMMARY": "event"}})
	}
	if err := idx.Batch(batch); err != nil {
		t.Fatal(err)
	}
	if err := idx.Close(); err != nil {
		t.Fatal(err)
	}
	size := indexBytes(t, root)
	t.Logf("corpus: %d raw bytes, %d extracted text bytes; index: %d bytes (%.1f%% of raw mail, %.2fx extracted text)",
		rawBytes, textBytes, size, 100*float64(size)/float64(rawBytes), float64(size)/float64(textBytes))
	// v9 measured 229% of the raw corpus here; v10 measures about 33%.
	if size*2 > rawBytes {
		t.Fatalf("index is %d bytes for %d bytes of mail; want under half", size, rawBytes)
	}
}

func TestExtractionIndexesEachTextOnce(t *testing.T) {
	folder := model.Folder{ID: "inbox", Type: model.FolderTypeMail}
	raw := strings.Join([]string{
		"From: a@example.test", "Subject: Plan",
		"DKIM-Signature: v=1; a=rsa-sha256; d=signer.example; s=sel1;\r\n b=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
		"Content-Type: multipart/alternative; boundary=alt", "", "--alt",
		"Content-Type: text/plain", "", "plain rendering words", "--alt",
		"Content-Type: text/html", "", "<p>html rendering words</p>", "--alt",
		"Content-Type: text/calendar", "", "BEGIN:VEVENT\r\nSUMMARY:standup\r\nEND:VEVENT", "--alt--", "",
	}, "\r\n")
	doc := extract(folder, model.Item{ID: "i1", FolderID: "inbox", Data: []byte(raw),
		Headers: map[string]string{"Subject": "Plan", "X-Veksel-Command-ID": "cmd-random-token", "X-Origin": "importer"}}, 0)
	if strings.Contains(doc.Content, "plain rendering") || !strings.Contains(doc.Content, "html rendering words") || !strings.Contains(doc.Content, "standup") {
		t.Fatalf("alternative content = %q", doc.Content)
	}
	if strings.Contains(doc.Headers, "QUJD") || !strings.Contains(doc.Headers, "d=signer.example") || !strings.Contains(doc.Headers, "s=sel1") {
		t.Fatalf("signature header = %q", doc.Headers)
	}
	if strings.Contains(doc.Headers, "cmd-random-token") || strings.Count(doc.Headers, "Plan") != 1 || !strings.Contains(doc.Headers, "X-Origin: importer") {
		t.Fatalf("headers = %q", doc.Headers)
	}
	// One attachment cannot take the whole message budget, and a cut never
	// splits a UTF-8 sequence (which would reject the attachment as binary).
	large := strings.Repeat("æ", maxAttachmentTextBytes)
	raw = strings.Join([]string{
		"Content-Type: multipart/mixed; boundary=m", "", "--m", "Content-Type: text/plain", "", "body", "--m",
		"Content-Type: text/plain; charset=utf-8", "Content-Disposition: attachment; filename=a.txt", "", large, "--m",
		"Content-Type: text/plain; charset=utf-8", "Content-Disposition: attachment; filename=b.txt", "", "second attachment", "--m--", "",
	}, "\r\n")
	doc = extract(folder, model.Item{ID: "i2", FolderID: "inbox", Data: []byte(raw)}, 1<<20)
	if !doc.Truncated || len(doc.AttachmentText) > maxAttachmentTextBytes+64 || !strings.HasPrefix(doc.AttachmentText, "æ") || !strings.Contains(doc.AttachmentText, "second attachment") {
		t.Fatalf("attachment text: %d bytes, truncated=%v", len(doc.AttachmentText), doc.Truncated)
	}
}

// documentText is all extracted text of doc, the measure of extraction size.
func documentText(doc document) string {
	return strings.Join([]string{doc.Name, doc.Title, doc.Sender, doc.Recipients, doc.Subject, doc.Headers, doc.Content, doc.Attachment, doc.AttachmentText}, "\n")
}
