package migration

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
)

// TraceRemote returns ctx with a trace that remembers the address of the
// last connection a request used, and a function that reports it.
func TraceRemote(ctx context.Context) (context.Context, func() string) {
	var mu sync.Mutex
	var remote string
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if info.Conn == nil {
			return
		}
		mu.Lock()
		remote = info.Conn.RemoteAddr().String()
		mu.Unlock()
	}}
	return httptrace.WithClientTrace(ctx, trace), func() string {
		mu.Lock()
		defer mu.Unlock()
		return remote
	}
}

// CheckSourceResponse reports a response that is not what a protocol
// endpoint answers: a status other than 200, or a 200 web page (HTML from
// a proxy, firewall or login portal). The error names the status, media
// type, redirect target, URL and server address so an operator can see
// that the endpoint, not the protocol, is wrong. Accepted lists the media
// types the protocol uses; other non-HTML types are let through, since
// servers label protocol bodies inconsistently.
func CheckSourceResponse(protocol string, response *http.Response, remote string, bodyLength int, accepted ...string) error {
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	webPage := mediaType == "text/html" || mediaType == "application/xhtml+xml"
	if response.StatusCode == http.StatusOK && (bodyLength == 0 || !webPage || containsFold(accepted, mediaType)) {
		return nil
	}
	var detail []string
	detail = append(detail, fmt.Sprintf("HTTP %s", response.Status))
	if mediaType != "" {
		detail = append(detail, mediaType)
	}
	if location := response.Header.Get("Location"); location != "" {
		detail = append(detail, "redirect to "+location)
	}
	if challenge := response.Header.Values("WWW-Authenticate"); response.StatusCode == http.StatusUnauthorized && len(challenge) > 0 {
		detail = append(detail, "offers "+strings.Join(challengeSchemes(challenge), ", "))
	}
	where := ""
	if response.Request != nil && response.Request.URL != nil {
		where = " from " + response.Request.URL.Redacted()
	}
	if remote != "" {
		where += " at " + remote
	}
	hint := "check the endpoint URL and that its host name resolves to the server itself"
	switch {
	case response.StatusCode == http.StatusUnauthorized:
		hint = "check the user name (DOMAIN\\user or user@domain) and password"
	case response.StatusCode == http.StatusOK:
		hint = "the address answers, but not as " + protocol + "; " + hint
	}
	return fmt.Errorf("source answered %s, not an %s response%s: %s", strings.Join(detail, ", "), protocol, where, hint)
}

func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

func challengeSchemes(values []string) []string {
	schemes := make([]string, 0, len(values))
	for _, value := range values {
		scheme, _, _ := strings.Cut(strings.TrimSpace(value), " ")
		if scheme != "" {
			schemes = append(schemes, scheme)
		}
	}
	return schemes
}
