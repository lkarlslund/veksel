package main

import (
	"context"
	"errors"
	"testing"
)

type identityResolver struct {
	hosts []string
	ptrs  []string
	err   error
}

func (r identityResolver) LookupHost(context.Context, string) ([]string, error) {
	return r.hosts, r.err
}
func (r identityResolver) LookupAddr(context.Context, string) ([]string, error) { return r.ptrs, nil }

func TestSMTPIdentityProblems(t *testing.T) {
	resolves := identityResolver{hosts: []string{"192.0.2.1"}, ptrs: []string{"mail.example.com."}}
	missing := identityResolver{err: errors.New("no such host")}
	for _, test := range []struct {
		name, addr string
		r          identityResolver
		want       int
	}{
		{"mail.example.com", "", resolves, 0},
		{"mail.example.com.", "", resolves, 0},
		{"veksel", "", resolves, 1},
		{"192.0.2.1", "", resolves, 1},
		{"mail.example.com", "", missing, 1},
		{"mail.example.com", "192.0.2.1", resolves, 0},
		{"mail.example.com", "192.0.2.7", resolves, 1},
	} {
		if got := smtpIdentityProblems(context.Background(), test.name, test.addr, test.r); len(got) != test.want {
			t.Errorf("%q %q: problems = %v, want %d", test.name, test.addr, got, test.want)
		}
	}
}
