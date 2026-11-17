package ntlm

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
)

// Transport authenticates requests that carry Basic credentials
// (http.Request.SetBasicAuth) with whatever the server asks for: NTLM or
// Negotiate (answered with NTLM) when offered, otherwise Basic when
// AllowBasic is set.
//
// NTLM authenticates a connection, so the handshake needs HTTP/1.1 with
// keep-alive: Base must not negotiate HTTP/2, which IIS refuses for NTLM.
// IIS keeps an NTLM-authenticated connection signed in, so later requests on
// it pass without a new handshake.
type Transport struct {
	// Base sends the requests; nil uses http.DefaultTransport.
	Base http.RoundTripper
	// AllowBasic sends Basic credentials when the server offers Basic but
	// neither NTLM nor Negotiate.
	AllowBasic bool
	// Observe, when set, is called once per request with how it went.
	Observe func(Exchange)

	// MaxSessions bounds the pinned connections per host (default 8).
	MaxSessions int

	basicHosts sync.Map // hosts that accepted Basic; sent preemptively

	sessionsMu sync.Mutex
	sessions   map[string]*sessionPool
}

// sessionPool holds single-connection transports for one host. A request
// takes one exclusively for its whole handshake and response, so the NTLM
// CHALLENGE and AUTHENTICATE messages always travel on the same connection
// even when requests run concurrently, and the connection stays signed in
// for the next request that takes the session.
type sessionPool struct {
	idle    chan *http.Transport
	created int
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// RoundTrip implements http.RoundTripper.
// Exchange describes one authenticated request: the statuses of each
// attempt in order, the scheme that was used, and the server address.
type Exchange struct {
	Method   string
	URL      string
	User     string
	Remote   string
	Scheme   string // "", "Basic", "NTLM" or "Negotiate" (NTLM inside SPNEGO)
	Statuses []int
	Err      error
}

func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	exchange := Exchange{Method: request.Method, URL: request.URL.Redacted()}
	ctx := httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if info.Conn != nil {
			exchange.Remote = info.Conn.RemoteAddr().String()
		}
	}})
	transport, release := t.acquire(request)
	response, err := t.roundTrip(request.WithContext(ctx), transport, &exchange)
	if err != nil || response == nil {
		release()
	} else {
		response.Body = &releaseOnClose{ReadCloser: response.Body, release: release}
	}
	if t.Observe != nil {
		exchange.Err = err
		t.Observe(exchange)
	}
	return response, err
}

func (t *Transport) roundTrip(request *http.Request, base http.RoundTripper, exchange *Exchange) (*http.Response, error) {
	user, password, ok := request.BasicAuth()
	exchange.User = user
	if !ok {
		response, err := base.RoundTrip(request)
		if err == nil {
			exchange.Statuses = append(exchange.Statuses, response.StatusCode)
		}
		return response, err
	}
	body, err := replayableBody(request)
	if err != nil {
		return nil, err
	}
	send := func(authorization string) (*http.Response, error) {
		attempt := request.Clone(request.Context())
		attempt.Header.Del("Authorization")
		if authorization != "" {
			attempt.Header.Set("Authorization", authorization)
		}
		if attempt.Body, err = body(); err != nil {
			return nil, err
		}
		response, err := base.RoundTrip(attempt)
		if err == nil {
			exchange.Statuses = append(exchange.Statuses, response.StatusCode)
		}
		return response, err
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	if _, known := t.basicHosts.Load(request.URL.Host); known && t.AllowBasic {
		exchange.Scheme = "Basic"
		response, err := send(basic)
		if err != nil || response.StatusCode != http.StatusUnauthorized {
			return response, err
		}
		t.basicHosts.Delete(request.URL.Host)
		drain(response)
	}

	response, err := send("")
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		return response, err
	}
	scheme := offeredScheme(response.Header, t.AllowBasic)
	switch scheme {
	case "":
		return response, nil
	case "Basic":
		exchange.Scheme = "Basic"
		drain(response)
		response, err = send(basic)
		if err == nil && response.StatusCode != http.StatusUnauthorized {
			t.basicHosts.Store(request.URL.Host, true)
		}
		return response, err
	}
	exchange.Scheme = scheme
	drain(response)
	response, err = send(scheme + " " + base64.StdEncoding.EncodeToString(Negotiate()))
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		return response, err
	}
	token, found := challengeToken(response.Header, scheme)
	if !found {
		return response, nil
	}
	binding := Binding{ServicePrincipal: "HTTP/" + request.URL.Hostname()}
	if state := response.TLS; state != nil && len(state.PeerCertificates) > 0 {
		binding.ChannelBindings = TLSChannelBindings(state.PeerCertificates[0])
	}
	drain(response)
	challenge, err := ParseChallenge(token)
	if err != nil {
		return nil, err
	}
	message, err := Authenticate(challenge, Credentials{User: user, Password: password}, binding)
	if err != nil {
		return nil, err
	}
	return send(scheme + " " + base64.StdEncoding.EncodeToString(message))
}

// replayableBody returns a function yielding a fresh copy of the request
// body for each attempt of the handshake.
func replayableBody(request *http.Request) (func() (io.ReadCloser, error), error) {
	if request.Body == nil || request.Body == http.NoBody {
		return func() (io.ReadCloser, error) { return http.NoBody, nil }, nil
	}
	if request.GetBody != nil {
		_ = request.Body.Close()
		return request.GetBody, nil
	}
	data, err := io.ReadAll(request.Body)
	_ = request.Body.Close()
	if err != nil {
		return nil, err
	}
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }, nil
}

// offeredScheme picks NTLM, then Negotiate, then (when allowed) Basic from
// the server's challenges.
func offeredScheme(header http.Header, allowBasic bool) string {
	var negotiate, basic bool
	for _, value := range header.Values("WWW-Authenticate") {
		name, _, _ := strings.Cut(strings.TrimSpace(value), " ")
		switch {
		case strings.EqualFold(name, "NTLM"):
			return "NTLM"
		case strings.EqualFold(name, "Negotiate"):
			negotiate = true
		case strings.EqualFold(name, "Basic"):
			basic = true
		}
	}
	switch {
	case negotiate:
		return "Negotiate"
	case basic && allowBasic:
		return "Basic"
	}
	return ""
}

func challengeToken(header http.Header, scheme string) ([]byte, bool) {
	for _, value := range header.Values("WWW-Authenticate") {
		name, token, _ := strings.Cut(strings.TrimSpace(value), " ")
		if !strings.EqualFold(name, scheme) || strings.TrimSpace(token) == "" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
		if err == nil {
			return data, true
		}
	}
	return nil, false
}

// acquire returns the transport to send request with and a function that
// gives it back. With an *http.Transport base, that is a pinned
// single-connection session; any other base is used as is.
func (t *Transport) acquire(request *http.Request) (http.RoundTripper, func()) {
	base, ok := t.base().(*http.Transport)
	if !ok {
		return t.base(), func() {}
	}
	key := request.URL.Scheme + "://" + request.URL.Host
	t.sessionsMu.Lock()
	if t.sessions == nil {
		t.sessions = map[string]*sessionPool{}
	}
	limit := t.MaxSessions
	if limit <= 0 {
		limit = 8
	}
	pool := t.sessions[key]
	if pool == nil {
		pool = &sessionPool{idle: make(chan *http.Transport, limit)}
		t.sessions[key] = pool
	}
	var session *http.Transport
	select {
	case session = <-pool.idle:
	default:
		if pool.created < limit {
			pool.created++
			session = base.Clone()
			session.MaxConnsPerHost = 1
			session.MaxIdleConnsPerHost = 1
		}
	}
	t.sessionsMu.Unlock()
	if session == nil {
		select {
		case session = <-pool.idle:
		case <-request.Context().Done():
			return failingRoundTripper{request.Context().Err()}, func() {}
		}
	}
	var once sync.Once
	return session, func() { once.Do(func() { pool.idle <- session }) }
}

type failingRoundTripper struct{ err error }

func (f failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// releaseOnClose gives the session back once the caller is done with the
// response body, so the connection is free for the next request.
type releaseOnClose struct {
	io.ReadCloser
	release func()
}

func (r *releaseOnClose) Close() error {
	err := r.ReadCloser.Close()
	r.release()
	return err
}

func drain(response *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
}

// HTTP1Only turns HTTP/2 off on transport so NTLM handshakes keep their
// connection.
func HTTP1Only(transport *http.Transport) *http.Transport {
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
	return transport
}
