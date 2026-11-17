package ban

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type auditEntry struct{ actor, action, target string }

type fakeAudit struct {
	mu      sync.Mutex
	entries []auditEntry
}

func (a *fakeAudit) Log(actor, action, target string, _ map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, auditEntry{actor, action, target})
}

type fakeMetrics struct {
	mu       sync.Mutex
	counters map[string]float64
	gauges   map[string]float64
}

func (m *fakeMetrics) IncrementCounter(name string, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, value := range labels {
		name += ":" + value
	}
	m.counters[name]++
}

func (m *fakeMetrics) SetGauge(name string, value float64, _ map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[name] = value
}

type harness struct {
	backend store.Store
	audit   *fakeAudit
	metrics *fakeMetrics
	now     time.Time
	service *Service
}

func testPolicy() Policy {
	policy := DefaultPolicy()
	policy.Rules = map[Trigger]Rule{
		TriggerAuth: {3, 10 * time.Minute}, TriggerSecondFactor: {2, 10 * time.Minute},
		TriggerRecipient: {4, time.Minute}, TriggerProtocol: {5, 10 * time.Minute},
	}
	return policy
}

func newHarness(t *testing.T, policy Policy) *harness {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	h := &harness{backend: backend, audit: &fakeAudit{}, metrics: &fakeMetrics{counters: map[string]float64{}, gauges: map[string]float64{}}, now: time.Unix(1_800_000_000, 0)}
	h.service = h.open(t, policy)
	return h
}

func (h *harness) open(t *testing.T, policy Policy) *Service {
	t.Helper()
	service, err := New(t.Context(), h.backend, h.audit, h.metrics, policy)
	if err != nil {
		t.Fatal(err)
	}
	service.SetClock(func() time.Time { return h.now })
	service.mu.Lock()
	service.reindexLocked()
	service.mu.Unlock()
	return service
}

func (h *harness) strike(ip string, trigger Trigger, times int) {
	for range times {
		h.service.Strike(ip, trigger)
	}
}

func TestStrikesBanAtThresholdWithinWindow(t *testing.T) {
	h := newHarness(t, testPolicy())
	h.strike("192.0.2.1", TriggerRecipient, 3)
	if h.service.Banned("192.0.2.1", "smtp") {
		t.Fatal("banned below the threshold")
	}
	// Strikes older than the window no longer count.
	h.now = h.now.Add(2 * time.Minute)
	h.strike("192.0.2.1", TriggerRecipient, 3)
	if h.service.Banned("192.0.2.1", "smtp") {
		t.Fatal("strikes outside the window counted")
	}
	h.strike("192.0.2.1", TriggerRecipient, 1)
	if !h.service.Banned("192.0.2.1", "smtp") {
		t.Fatal("not banned at the threshold within the window")
	}
	if h.service.Banned("192.0.2.2", "smtp") {
		t.Fatal("another address banned")
	}
	bans := h.service.List("")
	if len(bans) != 1 || bans[0].Prefix != "192.0.2.1/32" || bans[0].Reason != TriggerRecipient || bans[0].Source != SourceAutomatic || bans[0].Strikes != 4 || bans[0].Hits != 1 || !bans[0].ExpiresAt.Equal(h.now.Add(10*time.Minute)) {
		t.Fatalf("bans = %+v", bans)
	}
	if h.metrics.counters["ban_created_total:rcpt_unknown"] != 1 || h.metrics.counters["ban_refused_total:smtp"] != 1 || h.metrics.gauges["ban_active"] != 1 {
		t.Fatalf("metrics = %v %v", h.metrics.counters, h.metrics.gauges)
	}
	if len(h.audit.entries) != 1 || h.audit.entries[0] != (auditEntry{"system", "security.ban.add", "192.0.2.1/32"}) {
		t.Fatalf("audit = %+v", h.audit.entries)
	}
}

func TestTriggersCountSeparatelyAndDisabledTriggerNeverBans(t *testing.T) {
	policy := testPolicy()
	policy.Rules[TriggerProtocol] = Rule{}
	h := newHarness(t, policy)
	h.strike("192.0.2.1", TriggerAuth, 2)
	h.strike("192.0.2.1", TriggerSecondFactor, 1)
	h.strike("192.0.2.1", TriggerProtocol, 100)
	if h.service.Banned("192.0.2.1", "imap") {
		t.Fatal("strikes of different triggers were combined or a disabled trigger banned")
	}
	h.strike("192.0.2.1", TriggerSecondFactor, 1)
	if !h.service.Banned("192.0.2.1", "imap") || h.service.List("")[0].Reason != TriggerSecondFactor {
		t.Fatalf("second-factor trigger did not ban: %+v", h.service.List(""))
	}
}

func TestBansEscalateExpireAndForgetHistory(t *testing.T) {
	h := newHarness(t, testPolicy())
	want := []time.Duration{10 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 7 * 24 * time.Hour}
	for i, duration := range want {
		h.strike("198.51.100.7", TriggerAuth, 3)
		bans := h.service.List("")
		if len(bans) != 1 || bans[0].Offense != i+1 || bans[0].ExpiresAt.Sub(bans[0].CreatedAt) != duration {
			t.Fatalf("offense %d bans = %+v", i+1, bans)
		}
		h.now = h.now.Add(duration - time.Second)
		if !h.service.Banned("198.51.100.7", "smtp") {
			t.Fatalf("offense %d expired early", i+1)
		}
		h.now = h.now.Add(time.Second)
		if h.service.Banned("198.51.100.7", "smtp") {
			t.Fatalf("offense %d did not expire", i+1)
		}
	}
	// After the offense memory the next ban starts over.
	h.now = h.now.Add(offenseMemory)
	h.service.Maintain(t.Context())
	if keys, err := h.backend.List(t.Context(), "bans"); err != nil || len(keys) != 0 {
		t.Fatalf("expired history kept: %v %v", keys, err)
	}
	h.strike("198.51.100.7", TriggerAuth, 3)
	if bans := h.service.List(""); len(bans) != 1 || bans[0].Offense != 1 {
		t.Fatalf("history not forgotten: %+v", bans)
	}
	if h.metrics.gauges["ban_active"] != 1 {
		t.Fatalf("active gauge = %v", h.metrics.gauges["ban_active"])
	}
}

func TestExemptionsAreNeverStruckOrRefused(t *testing.T) {
	policy := testPolicy()
	policy.Exempt = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	h := newHarness(t, policy)
	h.service.SetExemptCheck(func(addr netip.Addr) bool { return addr == netip.MustParseAddr("203.0.113.9") })
	for _, ip := range []string{"127.0.0.1", "::1", "10.1.2.3", "::ffff:10.1.2.3", "203.0.113.9", "", "not-an-ip", "0.0.0.0"} {
		h.strike(ip, TriggerAuth, 10)
	}
	if active := h.service.Active(); active != 0 {
		t.Fatalf("exempt addresses banned: %+v", h.service.List(""))
	}
	for _, network := range []string{"127.0.0.1", "10.0.0.0/16", "8.0.0.0/4", "203.0.113.9"} {
		if _, err := h.service.Ban(t.Context(), mustNetwork(t, network), time.Hour, "admin", ""); err != ErrExempt {
			t.Fatalf("manual ban of %s err = %v", network, err)
		}
	}
	// A network banned before it was exempted is no longer refused.
	h.strike("192.0.2.50", TriggerAuth, 3)
	policy.Exempt = append(policy.Exempt, netip.MustParsePrefix("192.0.2.0/24"))
	h.service.Configure(policy)
	if h.service.Banned("192.0.2.50", "smtp") {
		t.Fatal("newly exempt address refused")
	}
}

func TestSuccessfulLoginClearsStrikesAndShieldsTheWindow(t *testing.T) {
	h := newHarness(t, testPolicy())
	h.strike("192.0.2.1", TriggerAuth, 2)
	h.service.ObserveAuth("192.0.2.1", "alice", true)
	h.strike("192.0.2.1", TriggerAuth, 5)
	if h.service.Banned("192.0.2.1", "imap") {
		t.Fatal("authenticated network banned within the window")
	}
	h.now = h.now.Add(11 * time.Minute)
	h.service.ObserveAuth("192.0.2.1", "alice", false)
	h.service.ObserveAuth("192.0.2.1", "bob", false)
	h.service.ObserveAuth("192.0.2.1", ratelimit.SecondFactorAccount("alice"), false)
	if h.service.Banned("192.0.2.1", "imap") {
		t.Fatal("banned before the threshold")
	}
	h.service.ObserveAuth("192.0.2.1", "carol", false)
	if !h.service.Banned("192.0.2.1", "imap") || h.service.List("")[0].Reason != TriggerAuth {
		t.Fatalf("failed logins after the window did not ban: %+v", h.service.List(""))
	}
}

func TestIPv6ClientsAreGroupedByPrefix(t *testing.T) {
	h := newHarness(t, testPolicy())
	h.strike("2001:db8:1:2::1", TriggerAuth, 1)
	h.strike("2001:db8:1:2::2", TriggerAuth, 1)
	h.strike("2001:db8:1:2:ffff::3", TriggerAuth, 1)
	if !h.service.Banned("2001:db8:1:2:abcd::9", "http") || h.service.Banned("2001:db8:1:3::1", "http") {
		t.Fatal("IPv6 /64 not grouped")
	}
	if bans := h.service.List("2001:db8"); len(bans) != 1 || bans[0].Prefix != "2001:db8:1:2::/64" {
		t.Fatalf("bans = %+v", bans)
	}
	policy := testPolicy()
	policy.IPv6Prefix = 128
	h.service.Configure(policy)
	h.strike("2001:db8:9::1", TriggerAuth, 2)
	h.strike("2001:db8:9::2", TriggerAuth, 2)
	if h.service.Banned("2001:db8:9::3", "http") {
		t.Fatal("/128 grouping banned a neighbour")
	}
}

func TestManualBanUnbanAndPersistenceAcrossRestart(t *testing.T) {
	h := newHarness(t, testPolicy())
	ban, err := h.service.Ban(t.Context(), mustNetwork(t, "198.51.100.0/24"), 2*time.Hour, "owner", "scanner")
	if err != nil || ban.Prefix != "198.51.100.0/24" || ban.Source != SourceManual || ban.Reason != TriggerManual || ban.Actor != "owner" {
		t.Fatalf("manual ban = %+v err=%v", ban, err)
	}
	h.strike("2001:db8::1", TriggerAuth, 3)
	if !h.service.Banned("198.51.100.42", "imap") {
		t.Fatal("manual CIDR ban not enforced")
	}
	h.service.Maintain(t.Context())

	restarted := h.open(t, testPolicy())
	h.service = restarted
	if !restarted.Banned("198.51.100.1", "imap") || !restarted.Banned("2001:db8::abcd", "smtp") {
		t.Fatal("bans not restored after restart")
	}
	bans := restarted.List("scanner")
	if len(bans) != 1 || bans[0].Hits != 2 || bans[0].Comment != "scanner" {
		t.Fatalf("restored bans = %+v", bans)
	}
	if err := restarted.Unban(t.Context(), mustNetwork(t, "198.51.100.0/24"), "owner"); err != nil {
		t.Fatal(err)
	}
	if restarted.Banned("198.51.100.1", "imap") {
		t.Fatal("unbanned network still refused")
	}
	if err := restarted.Unban(t.Context(), mustNetwork(t, "198.51.100.0/24"), "owner"); err != ErrNotFound {
		t.Fatalf("second unban err = %v", err)
	}
	if again := h.open(t, testPolicy()); again.Banned("198.51.100.1", "imap") {
		t.Fatal("unban not persisted")
	}
	last := h.audit.entries[len(h.audit.entries)-1]
	if last != (auditEntry{"owner", "security.ban.remove", "198.51.100.0/24"}) {
		t.Fatalf("audit = %+v", h.audit.entries)
	}
}

func TestDisabledEngineNeitherBansNorEnforces(t *testing.T) {
	h := newHarness(t, testPolicy())
	h.strike("192.0.2.1", TriggerAuth, 3)
	policy := testPolicy()
	policy.Enabled = false
	h.service.Configure(policy)
	if h.service.Banned("192.0.2.1", "smtp") {
		t.Fatal("disabled engine enforced a ban")
	}
	h.strike("192.0.2.2", TriggerAuth, 10)
	if h.service.Active() != 1 {
		t.Fatal("disabled engine banned")
	}
	if observation := h.service.Observation(); observation.State != health.StateDisabled {
		t.Fatalf("observation = %+v", observation)
	}
	policy.Enabled = true
	h.service.Configure(policy)
	if !h.service.Banned("192.0.2.1", "smtp") {
		t.Fatal("re-enabled engine forgot the ban")
	}
	if observation := h.service.Observation(); observation.State != health.StateHealthy {
		t.Fatalf("observation = %+v", observation)
	}
}

func TestListenerClosesBannedConnectionsAndHandlerRefuses(t *testing.T) {
	h := newHarness(t, testPolicy())
	if _, err := h.service.Ban(t.Context(), mustNetwork(t, "192.0.2.66"), time.Hour, "owner", ""); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 2)
	ln := h.service.Listener(&scriptedListener{conns: []net.Conn{fakeConn("192.0.2.66:1000"), fakeConn("192.0.2.67:1000")}}, "imap")
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	conn := <-accepted
	if conn.RemoteAddr().String() != "192.0.2.67:1000" {
		t.Fatalf("accepted %s", conn.RemoteAddr())
	}

	handler := h.service.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	request := httptest.NewRequest(http.MethodGet, "/app/", nil)
	request.RemoteAddr = "10.0.0.1:5000"
	request = request.WithContext(ratelimit.WithClientIP(request.Context(), "192.0.2.66"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || recorder.Body.String() != "Forbidden\n" {
		t.Fatalf("banned request = %d %q", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/app/", nil)
	request.RemoteAddr = "192.0.2.66:5000"
	request = request.WithContext(ratelimit.WithClientIP(request.Context(), "198.51.100.1"))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("request from an unbanned effective client = %d", recorder.Code)
	}
}

func TestAbnormalTableWarnsInHealth(t *testing.T) {
	h := newHarness(t, testPolicy())
	h.service.mu.Lock()
	for i := range AbnormalActive {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32)
		h.service.records[prefix] = newRecord(Ban{Prefix: prefix.String(), ExpiresAt: h.now.Add(time.Hour)}, prefix)
	}
	h.service.reindexLocked()
	h.service.mu.Unlock()
	if observation := h.service.Observation(); observation.State != health.StateDegraded || observation.Severity != health.SeverityWarning {
		t.Fatalf("observation = %+v", observation)
	}
}

func mustNetwork(t *testing.T, value string) netip.Prefix {
	t.Helper()
	network, err := ParseNetwork(value)
	if err != nil {
		t.Fatal(err)
	}
	return network
}

type scriptedListener struct {
	mu    sync.Mutex
	conns []net.Conn
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) == 0 {
		return nil, net.ErrClosed
	}
	conn := l.conns[0]
	l.conns = l.conns[1:]
	return conn, nil
}

func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }
func (c addrConn) Close() error         { return nil }

func fakeConn(remote string) net.Conn {
	addr, _ := net.ResolveTCPAddr("tcp", remote)
	return addrConn{remote: addr}
}
