package queue

import (
	"context"
	"errors"
	"testing"
)

func TestAdministrativeCopiesJoinTheBatchWithoutAdmission(t *testing.T) {
	admitted := 0
	q := New(&Config{
		Admission: func(context.Context, *Message) error { admitted++; return nil },
		Copies: func(_ context.Context, batch []*Message) ([]*Message, error) {
			if batch[0].Recipient == "fail@remote.test" {
				return nil, errors.New("copy rules unavailable")
			}
			return []*Message{{ID: batch[0].ID + ".copy", Kind: "bcc", ParentID: batch[0].ID, CorrelationID: batch[0].CorrelationID, Recipient: "archive@remote.test"}}, nil
		},
	})
	t.Cleanup(q.Close)
	if err := q.EnqueueBatch([]*Message{{ID: "original", Recipient: "carol@remote.test", CorrelationID: "submission"}}); err != nil {
		t.Fatal(err)
	}
	copied := q.Get("original.copy")
	if admitted != 1 || copied == nil || copied.Status != StatusPending || copied.CorrelationID != "submission" || copied.ExpiresAt.IsZero() {
		t.Fatalf("admitted=%d copy=%+v", admitted, copied)
	}
	// A failing copy rule refuses the whole batch, and a replay stays a
	// duplicate of the original and its copy.
	if err := q.Enqueue(&Message{ID: "other", Recipient: "fail@remote.test"}); err == nil || q.Get("other") != nil {
		t.Fatalf("batch with failing copies admitted: %v", err)
	}
	if err := q.Enqueue(&Message{ID: "original", Recipient: "carol@remote.test"}); !errors.Is(err, ErrDuplicate) || q.Size() != 2 {
		t.Fatalf("replay = %v, size %d", err, q.Size())
	}
}
