package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// adAccountDisable is the ACCOUNTDISABLE bit of Active Directory's
// userAccountControl attribute.
const adAccountDisable = 0x2

// maxPooledConnections bounds the idle service-bound connections kept for
// reuse; concurrent logins beyond it dial their own and close them after.
const maxPooledConnections = 4

// syncPageSize is the paged-results size used to list directory users.
const syncPageSize = 500

// LDAP is a Directory backed by one or more LDAP servers. It searches with the
// service account and verifies passwords by binding as the single entry the
// search found. Service-bound connections are pooled and servers are tried in
// order, starting with the last one that answered.
type LDAP struct {
	settings Settings
	tls      *tls.Config

	mu        sync.Mutex
	idle      []*ldap.Conn
	preferred int
	closed    bool
}

// NewLDAP validates settings and returns a client. It does not connect.
func NewLDAP(settings Settings) (*LDAP, error) {
	if len(settings.URLs) == 0 {
		return nil, errors.New("no directory server URLs are configured")
	}
	if settings.BaseDN == "" {
		return nil, errors.New("no directory base DN is configured")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if pem := strings.TrimSpace(settings.CACertificate); pem != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(pem)) {
			return nil, errors.New("directory CA certificate contains no PEM certificate")
		}
		tlsConfig.RootCAs = roots
	}
	if settings.Timeout <= 0 {
		settings.Timeout = 10 * time.Second
	}
	return &LDAP{settings: settings, tls: tlsConfig}, nil
}

// Authenticate implements Directory.
func (c *LDAP) Authenticate(ctx context.Context, login, password string) (Entry, error) {
	if password == "" || strings.TrimSpace(login) == "" {
		return Entry{}, ErrInvalidCredentials
	}
	conn, err := c.acquire(ctx)
	if err != nil {
		return Entry{}, err
	}
	healthy := false
	defer func() { c.release(conn, healthy) }()
	request := c.searchRequest(UserFilter(c.settings.UserFilter, login), 2)
	result, err := conn.Search(request)
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || err == nil && len(result.Entries) > 1:
		healthy = true
		return Entry{}, ErrAmbiguousLogin
	case err != nil:
		return Entry{}, fmt.Errorf("search directory: %w", err)
	case len(result.Entries) == 0:
		healthy = true
		return Entry{}, ErrInvalidCredentials
	}
	found := result.Entries[0]
	// Bind as the entry on the same connection, then restore the service
	// identity before the connection returns to the pool.
	if err := conn.Bind(found.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			healthy = c.bindService(conn) == nil
			return Entry{}, ErrInvalidCredentials
		}
		return Entry{}, fmt.Errorf("bind as directory user: %w", err)
	}
	if err := c.bindService(conn); err != nil {
		return Entry{}, fmt.Errorf("restore service bind: %w", err)
	}
	healthy = true
	admins, err := c.adminMembers(conn)
	if err != nil {
		return Entry{}, err
	}
	return c.entry(found, admins), nil
}

// Users implements Directory.
func (c *LDAP) Users(ctx context.Context, limit int) ([]Entry, error) {
	conn, err := c.acquire(ctx)
	if err != nil {
		return nil, err
	}
	healthy := false
	defer func() { c.release(conn, healthy) }()
	request := c.searchRequest(c.settings.SyncFilter, limit+1)
	result, err := conn.SearchWithPaging(request, syncPageSize)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || err == nil && len(result.Entries) > limit {
		return nil, fmt.Errorf("directory sync filter matches more than %d entries", limit)
	}
	if err != nil {
		return nil, fmt.Errorf("search directory: %w", err)
	}
	admins, err := c.adminMembers(conn)
	if err != nil {
		return nil, err
	}
	healthy = true
	entries := make([]Entry, 0, len(result.Entries))
	for _, found := range result.Entries {
		if entry := c.entry(found, admins); entry.Login != "" {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// Test implements Directory.
func (c *LDAP) Test(ctx context.Context) Diagnostic {
	diagnostic := Diagnostic{BaseDN: c.settings.BaseDN, BindDN: c.settings.BindDN}
	step := func(name string, started time.Time, err error, detail string) bool {
		result := DiagnosticStep{Name: name, OK: err == nil, Detail: detail, Milliseconds: time.Since(started).Milliseconds()}
		if err != nil {
			result.Detail = err.Error()
		}
		diagnostic.Steps = append(diagnostic.Steps, result)
		return err == nil
	}
	started := time.Now()
	conn, server, err := c.dial(ctx)
	if !step("connect", started, err, server) {
		return diagnostic
	}
	defer conn.Close()
	diagnostic.Server = server
	diagnostic.Transport = c.transport(server)
	started = time.Now()
	if !step("service bind", started, c.bindService(conn), "bound as "+bindName(c.settings.BindDN)) {
		return diagnostic
	}
	started = time.Now()
	result, err := conn.Search(c.searchRequest(c.settings.SyncFilter, 5))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) && result != nil {
		err = nil
	}
	if err == nil {
		for _, found := range result.Entries {
			diagnostic.Sample = append(diagnostic.Sample, DiagnosticEntry{DN: found.DN, Login: c.entry(found, groupMembers{}).Login})
		}
	}
	if !step("sample search", started, err, fmt.Sprintf("%d sample entries under the base DN", len(diagnostic.Sample))) {
		return diagnostic
	}
	if c.settings.AdminGroupDN != "" {
		started = time.Now()
		admins, err := c.adminMembers(conn)
		step("administrator group", started, err, fmt.Sprintf("%d direct members", len(admins.dns)+len(admins.logins)))
	}
	diagnostic.OK = true
	for _, s := range diagnostic.Steps {
		diagnostic.OK = diagnostic.OK && s.OK
	}
	return diagnostic
}

// Close releases pooled connections; the client cannot be used afterwards.
func (c *LDAP) Close() {
	c.mu.Lock()
	idle := c.idle
	c.idle, c.closed = nil, true
	c.mu.Unlock()
	for _, conn := range idle {
		_ = conn.Close()
	}
}

func (c *LDAP) searchRequest(filter string, sizeLimit int) *ldap.SearchRequest {
	attributes := append(slices.Clone(c.settings.IDAttributes), "displayName", "cn", "mail", "proxyAddresses", "userAccountControl", "memberOf", "objectGUID", "entryUUID")
	return ldap.NewSearchRequest(c.settings.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, sizeLimit,
		int(c.settings.Timeout/time.Second), false, filter, attributes, nil)
}

// acquire returns an idle service-bound connection or dials a new one.
func (c *LDAP) acquire(ctx context.Context) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrUnavailable
	}
	for len(c.idle) > 0 {
		conn := c.idle[len(c.idle)-1]
		c.idle = c.idle[:len(c.idle)-1]
		if !conn.IsClosing() {
			c.mu.Unlock()
			return conn, nil
		}
		_ = conn.Close()
	}
	c.mu.Unlock()
	conn, _, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.bindService(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("service bind: %w", err)
	}
	return conn, nil
}

func (c *LDAP) release(conn *ldap.Conn, healthy bool) {
	c.mu.Lock()
	if healthy && !c.closed && len(c.idle) < maxPooledConnections && !conn.IsClosing() {
		c.idle = append(c.idle, conn)
		conn = nil
	}
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// dial connects to the first server that answers, starting with the last
// one that did, and secures ldap:// with StartTLS unless plaintext is allowed.
func (c *LDAP) dial(ctx context.Context) (*ldap.Conn, string, error) {
	c.mu.Lock()
	start := c.preferred
	c.mu.Unlock()
	var failures []error
	for offset := range c.settings.URLs {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		index := (start + offset) % len(c.settings.URLs)
		server := strings.TrimSpace(c.settings.URLs[index])
		conn, err := c.dialServer(ctx, server)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", server, err))
			continue
		}
		c.mu.Lock()
		c.preferred = index
		c.mu.Unlock()
		return conn, server, nil
	}
	return nil, "", fmt.Errorf("%w: %w", ErrUnavailable, errors.Join(failures...))
}

func (c *LDAP) dialServer(ctx context.Context, server string) (*ldap.Conn, error) {
	parsed, err := url.Parse(server)
	if err != nil {
		return nil, err
	}
	tlsConfig := c.tls.Clone()
	tlsConfig.ServerName = parsed.Hostname()
	timeout := c.settings.Timeout
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = max(time.Until(deadline), time.Millisecond)
	}
	conn, err := ldap.DialURL(server, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(c.settings.Timeout)
	if parsed.Scheme == "ldap" && !c.settings.AllowPlaintext {
		if err := conn.StartTLS(tlsConfig); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("StartTLS: %w", err)
		}
	}
	return conn, nil
}

func (c *LDAP) transport(server string) string {
	switch {
	case strings.HasPrefix(server, "ldaps://"):
		return "ldaps"
	case c.settings.AllowPlaintext:
		return "plaintext"
	default:
		return "starttls"
	}
}

// bindService authenticates the connection as the service account, or
// leaves it anonymous when no bind DN is configured.
func (c *LDAP) bindService(conn *ldap.Conn) error {
	if c.settings.BindDN == "" {
		return conn.UnauthenticatedBind("")
	}
	return conn.Bind(c.settings.BindDN, c.settings.BindPassword)
}

func bindName(dn string) string {
	if dn == "" {
		return "anonymous"
	}
	return dn
}

// groupMembers holds the administrator group's direct members, by DN
// (member, uniqueMember) and by login (memberUid).
type groupMembers struct {
	dns    []*ldap.DN
	logins map[string]bool
}

func (c *LDAP) adminMembers(conn *ldap.Conn) (groupMembers, error) {
	members := groupMembers{logins: map[string]bool{}}
	if c.settings.AdminGroupDN == "" {
		return members, nil
	}
	request := ldap.NewSearchRequest(c.settings.AdminGroupDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		int(c.settings.Timeout/time.Second), false, "(objectClass=*)", []string{"member", "uniqueMember", "memberUid"}, nil)
	result, err := conn.Search(request)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return members, nil
	}
	if err != nil {
		return members, fmt.Errorf("read administrator group: %w", err)
	}
	for _, group := range result.Entries {
		for _, value := range append(group.GetEqualFoldAttributeValues("member"), group.GetEqualFoldAttributeValues("uniqueMember")...) {
			if dn, err := ldap.ParseDN(value); err == nil {
				members.dns = append(members.dns, dn)
			}
		}
		for _, login := range group.GetEqualFoldAttributeValues("memberUid") {
			members.logins[strings.ToLower(login)] = true
		}
	}
	return members, nil
}

// entry projects an LDAP entry onto the attributes Veksel uses.
func (c *LDAP) entry(found *ldap.Entry, admins groupMembers) Entry {
	entry := Entry{DN: found.DN}
	for _, attribute := range c.settings.IDAttributes {
		if value := strings.TrimSpace(found.GetEqualFoldAttributeValue(attribute)); value != "" {
			entry.Login = strings.ToLower(value)
			break
		}
	}
	if guid := found.GetEqualFoldRawAttributeValue("objectGUID"); len(guid) == 16 {
		entry.GUID = formatObjectGUID(guid)
	} else {
		entry.GUID = strings.ToLower(found.GetEqualFoldAttributeValue("entryUUID"))
	}
	entry.DisplayName = strings.TrimSpace(found.GetEqualFoldAttributeValue("displayName"))
	if entry.DisplayName == "" {
		entry.DisplayName = strings.TrimSpace(found.GetEqualFoldAttributeValue("cn"))
	}
	entry.Addresses = Addresses(found.GetEqualFoldAttributeValues("mail"), found.GetEqualFoldAttributeValues("proxyAddresses"))
	if control, err := strconv.ParseInt(found.GetEqualFoldAttributeValue("userAccountControl"), 10, 64); err == nil {
		entry.Disabled = control&adAccountDisable != 0
	}
	if c.settings.AdminGroupDN != "" {
		entry.Admin = admins.logins[entry.Login] && entry.Login != ""
		group, err := ldap.ParseDN(c.settings.AdminGroupDN)
		for _, value := range found.GetEqualFoldAttributeValues("memberOf") {
			if member, parseErr := ldap.ParseDN(value); err == nil && parseErr == nil && member.EqualFold(group) {
				entry.Admin = true
			}
		}
		if self, err := ldap.ParseDN(found.DN); err == nil {
			for _, member := range admins.dns {
				if member.EqualFold(self) {
					entry.Admin = true
				}
			}
		}
	}
	return entry
}

// formatObjectGUID renders Active Directory's mixed-endian objectGUID in its
// usual string form.
func formatObjectGUID(raw []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(raw[0:4]), binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]), raw[8:10], raw[10:16])
}

// UserFilter substitutes the escaped login for every {login} placeholder so
// a login can never change the filter's structure.
func UserFilter(template, login string) string {
	return strings.ReplaceAll(template, "{login}", ldap.EscapeFilter(strings.TrimSpace(login)))
}

// Addresses returns the lowercased, de-duplicated email addresses of an
// entry: mail values first, then SMTP proxyAddresses with the primary
// ("SMTP:") before secondary ("smtp:") ones. Non-SMTP proxies are ignored.
func Addresses(mail, proxies []string) []string {
	var primary, secondary []string
	for _, proxy := range proxies {
		kind, address, found := strings.Cut(proxy, ":")
		switch {
		case !found || !strings.EqualFold(kind, "smtp"):
		case kind == "SMTP":
			primary = append(primary, address)
		default:
			secondary = append(secondary, address)
		}
	}
	var result []string
	for _, address := range slices.Concat(mail, primary, secondary) {
		address = strings.ToLower(strings.TrimSpace(address))
		if strings.Count(address, "@") == 1 && !strings.HasPrefix(address, "@") && !strings.HasSuffix(address, "@") && !slices.Contains(result, address) {
			result = append(result, address)
		}
	}
	return result
}
