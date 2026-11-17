package imap

import (
	"math"
	"reflect"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestStatusAndFetchPreserveMaximum63BitSizes(t *testing.T) {
	session := &Session{cfg: &Config{}}
	values, err := session.statusValues(model.Folder{
		ItemCount:    math.MaxInt64,
		LogicalBytes: math.MaxInt64,
	}, []string{"MESSAGES", "SIZE"})
	if err != nil {
		t.Fatalf("statusValues: %v", err)
	}
	want := []string{"MESSAGES", "9223372036854775807", "SIZE", "9223372036854775807"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("status values = %#v, want %#v", values, want)
	}

	parts, literals, err := session.parseFetchAttrs("RFC822.SIZE", model.Item{Size: math.MaxInt64})
	if err != nil {
		t.Fatalf("parseFetchAttrs: %v", err)
	}
	if len(literals) != 0 || !reflect.DeepEqual(parts, []string{"RFC822.SIZE 9223372036854775807"}) {
		t.Fatalf("FETCH parts=%#v literals=%#v", parts, literals)
	}
}

func TestStatusAndFetchRejectNegativeAccountingSizes(t *testing.T) {
	session := &Session{cfg: &Config{}}
	if _, err := session.statusValues(model.Folder{ItemCount: -1}, []string{"MESSAGES"}); err == nil {
		t.Fatal("negative folder item count was accepted")
	}
	if _, err := session.statusValues(model.Folder{LogicalBytes: -1}, []string{"SIZE"}); err == nil {
		t.Fatal("negative folder byte count was accepted")
	}
	if _, _, err := session.parseFetchAttrs("RFC822.SIZE", model.Item{Size: -1}); err == nil {
		t.Fatal("negative message size was accepted")
	}
}

func TestBodyPartialAcceptsMaximum63BitOriginWithoutOverflow(t *testing.T) {
	request, ok, err := parseBodyFetch("BODY[TEXT]<9223372036854775807.1>")
	if err != nil || !ok || request.partialFrom != math.MaxInt64 {
		t.Fatalf("parseBodyFetch: request=%#v ok=%t err=%v", request, ok, err)
	}
	item := model.Item{Data: []byte("Subject: size\r\n\r\nbody")}
	parts, literals, err := (&Session{}).parseFetchAttrs("BODY[TEXT]<9223372036854775807.1>", item)
	if err != nil {
		t.Fatalf("parseFetchAttrs: %v", err)
	}
	if len(parts) != 1 || len(literals) != 1 || len(literals[0].data) != 0 {
		t.Fatalf("partial FETCH parts=%#v literals=%#v", parts, literals)
	}
}
