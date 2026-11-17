package jmap

import (
	"net/mail"
	"testing"
)

func TestThreadIDSharedByOriginalAndReplies(t *testing.T) {
	t.Parallel()
	header := func(values ...string) mail.Header {
		h := mail.Header{}
		for n := 0; n < len(values); n += 2 {
			h[values[n]] = []string{values[n+1]}
		}
		return h
	}
	original := threadID(header("Message-Id", "<Root@x>", "Subject", "Plan"))
	reply := threadID(header("Message-Id", "<r1@x>", "In-Reply-To", "<root@x>", "Subject", "Re: Plan"))
	deep := threadID(header("Message-Id", "<r2@x>", "References", "<root@x> <r1@x>", "In-Reply-To", "<r1@x>", "Subject", "Re: Plan"))
	if original != reply || reply != deep {
		t.Fatalf("thread ids differ: %s %s %s", original, reply, deep)
	}
	if threadID(header("Message-Id", "<other@x>", "Subject", "Plan")) == original {
		t.Fatal("unrelated message joined the thread")
	}
}
