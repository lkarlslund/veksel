package threading

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

var day = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func TestHeaderHelpers(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{"<msg@example.com>": "msg@example.com", "msg@example.com": "msg@example.com", " <MSG@EXAMPLE.COM>  ": "msg@example.com", "": ""} {
		if got := CanonicalID(input); got != want {
			t.Errorf("CanonicalID(%q) = %q, want %q", input, got, want)
		}
	}
	for input, want := range map[string][]string{
		"<a@x> <b@x>":   {"a@x", "b@x"},
		"<a@x><B@x>":    {"a@x", "b@x"},
		"a@x, b@x":      {"a@x", "b@x"},
		"":              nil,
		"<a@x> junk <>": {"a@x"},
	} {
		if got := ParseIDs(input); !slices.Equal(got, want) {
			t.Errorf("ParseIDs(%q) = %v, want %v", input, got, want)
		}
	}
	for input, want := range map[string]string{"Hello": "Hello", "Re: Re: Fw: Re: Hello World": "Hello World", "R: Hello": "Hello", "Wg: Hello": "Hello", "SV: AW: Status": "Status", "Fwd:Report": "Report"} {
		if got := BaseSubject(input); got != want {
			t.Errorf("BaseSubject(%q) = %q, want %q", input, got, want)
		}
	}
	if got := Parents("<a@x> <b@x>", "<b@x>"); !slices.Equal(got, []string{"a@x", "b@x"}) {
		t.Fatalf("Parents de-duplication = %v", got)
	}
	var long string
	for n := range MaxParents + 10 {
		long += fmt.Sprintf("<m%d@x> ", n)
	}
	if got := Parents(long, ""); len(got) != MaxParents || got[0] != "m0@x" || got[len(got)-1] != fmt.Sprintf("m%d@x", MaxParents+9) {
		t.Fatalf("bounded parents = %v", got)
	}
	if RootKey(Message{ID: "c@x", Parents: []string{"a@x", "b@x"}}) != "a@x" || RootKey(Message{ID: "a@x"}) != "a@x" || RootKey(Message{Subject: "Re: Hi"}) != "subject:hi" {
		t.Fatal("RootKey does not prefer the oldest ancestor")
	}
}

func TestBuildFollowsReferenceChainsAndMissingParents(t *testing.T) {
	t.Parallel()
	messages := []Message{
		{ID: "c@x", Parents: []string{"a@x", "b@x"}, Date: day.Add(2 * time.Hour)},
		{ID: "a@x", Date: day},
		{ID: "other@x", Date: day.Add(time.Hour)},
		// Two replies to a root that is not present still form one thread.
		{ID: "r1@x", Parents: []string{"missing@x"}, Date: day.Add(3 * time.Hour)},
		{ID: "r2@x", Parents: []string{"missing@x", "r1@x"}, Date: day.Add(4 * time.Hour)},
		// In-Reply-To only, chained through an intermediate message.
		{ID: "b@x", Parents: []string{"a@x"}, Date: day.Add(time.Hour)},
		{Subject: "no id", Date: day},
		{Subject: "no id", Date: day},
	}
	threads := Build(messages, Options{})
	want := [][]int{{1, 5, 0}, {2}, {3, 4}, {6}, {7}}
	if !slices.EqualFunc(threads, want, slices.Equal[[]int]) {
		t.Fatalf("threads = %v, want %v", threads, want)
	}
	if Build(nil, Options{}) != nil {
		t.Fatal("empty input must return nil")
	}
}

func TestBuildSubjectFallbackIsGuarded(t *testing.T) {
	t.Parallel()
	messages := []Message{
		{ID: "orig@x", Subject: "Budget", Date: day},
		// No threading headers, reply prefix, two days later: joins.
		{ID: "reply@x", Subject: "RE: Budget", Date: day.Add(48 * time.Hour)},
		// Same subject months later: a new conversation.
		{ID: "late@x", Subject: "Re: Budget", Date: day.AddDate(0, 4, 0)},
		// Same subject without a reply prefix never merges.
		{ID: "again@x", Subject: "Budget", Date: day.AddDate(0, 2, 0)},
		// A message with headers is never re-threaded by subject.
		{ID: "hdr@x", Subject: "Re: Budget", Parents: []string{"elsewhere@x"}, Date: day.Add(72 * time.Hour)},
	}
	threads := Build(messages, Options{SubjectWindow: 30 * 24 * time.Hour})
	// The header-less reply joins the nearest earlier same-subject message;
	// everything else stays apart.
	if want := [][]int{{0, 1}, {2}, {3}, {4}}; !slices.EqualFunc(threads, want, slices.Equal[[]int]) {
		t.Fatalf("threads = %v, want %v", threads, want)
	}
	if len(Build(messages, Options{})) != 5 {
		t.Fatal("subject fallback must be opt-in")
	}
}
