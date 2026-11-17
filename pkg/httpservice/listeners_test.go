package httpservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
)

func selfSignedCertificate(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// testListenerSet answers every request with the listener's name and serves
// HTTPS listeners the certificate named by their assignment.
func testListenerSet(t *testing.T, certificates map[string]tls.Certificate) *ListenerSet {
	t.Helper()
	set := NewListenerSet(func(listener config.HTTPListener) http.Handler {
		return Handler(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, listener.Name) }))
	}, func(listener config.HTTPListener) (*tls.Config, error) {
		certificate, ok := certificates[listener.Certificate]
		if !ok {
			return nil, fmt.Errorf("unknown certificate %q", listener.Certificate)
		}
		return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, nil
	}, Timeouts{ReadHeader: time.Second, Idle: time.Second})
	set.Serve()
	t.Cleanup(set.Close)
	return set
}

func httpListener(id, address string) config.HTTPListener {
	return config.HTTPListener{ID: id, Name: id, Enabled: true, Transport: config.HTTPTransport, Address: address, Services: []string{"web"}}
}

func get(t *testing.T, client *http.Client, url string) (int, string, error) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body), nil
}

func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func TestListenerSetAddsRemovesAndUpdatesListenersLive(t *testing.T) {
	set := testListenerSet(t, nil)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	first := httpListener("first", "127.0.0.1:0")
	if err := set.Apply([]config.HTTPListener{first}); err != nil {
		t.Fatal(err)
	}
	firstAddr := set.Addrs()["first"]
	if _, body, err := get(t, client, "http://"+firstAddr+"/app/"); err != nil || body != "first" {
		t.Fatalf("first listener: body=%q err=%v", body, err)
	}

	// Adding a listener starts it; renaming and rebinding services of the
	// first applies in place on the same socket.
	first.Name, first.Services = "renamed", []string{"dav"}
	second := httpListener("second", "127.0.0.1:0")
	if err := set.Apply([]config.HTTPListener{first, second}); err != nil {
		t.Fatal(err)
	}
	if got := set.Addrs()["first"]; got != firstAddr {
		t.Fatalf("in-place change rebound %s to %s", firstAddr, got)
	}
	if status, _, err := get(t, client, "http://"+firstAddr+"/app/"); err != nil || status != http.StatusNotFound {
		t.Fatalf("unbound web service after update: status=%d err=%v", status, err)
	}
	if _, body, err := get(t, client, "http://"+firstAddr+"/dav/x"); err != nil || body != "renamed" {
		t.Fatalf("updated handler: body=%q err=%v", body, err)
	}
	if _, body, err := get(t, client, "http://"+set.Addrs()["second"]+"/app/"); err != nil || body != "second" {
		t.Fatalf("added listener: body=%q err=%v", body, err)
	}

	// Removing a listener stops it; disabling counts as removal.
	first.Enabled = false
	if err := set.Apply([]config.HTTPListener{first, second}); err != nil {
		t.Fatal(err)
	}
	if _, ok := set.Addrs()["first"]; ok {
		t.Fatal("disabled listener still running")
	}
	waitUntil(t, func() bool { _, _, err := get(t, client, "http://"+firstAddr+"/dav/x"); return err != nil })
}

func TestListenerSetRebindsOnAddressAndTransportChange(t *testing.T) {
	certificate := selfSignedCertificate(t, "one.example.test")
	set := testListenerSet(t, map[string]tls.Certificate{"stored:one": certificate})
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec -- self-signed test certificate
	address := freePort(t)
	listener := httpListener("main", address)
	if err := set.Apply([]config.HTTPListener{listener}); err != nil {
		t.Fatal(err)
	}
	if _, body, err := get(t, client, "http://"+address+"/"); err != nil || body != "main" {
		t.Fatalf("plain listener: body=%q err=%v", body, err)
	}
	// Same fixed port, new transport: the old socket hands the port over.
	listener.Transport, listener.Certificate = config.HTTPSTransport, "stored:one"
	if err := set.Apply([]config.HTTPListener{listener}); err != nil {
		t.Fatal(err)
	}
	if _, body, err := get(t, client, "https://"+address+"/"); err != nil || body != "main" {
		t.Fatalf("rebound HTTPS listener: body=%q err=%v", body, err)
	}
	// New address: the listener moves.
	moved := freePort(t)
	listener.Address = moved
	if err := set.Apply([]config.HTTPListener{listener}); err != nil {
		t.Fatal(err)
	}
	if _, body, err := get(t, client, "https://"+moved+"/"); err != nil || body != "main" {
		t.Fatalf("moved listener: body=%q err=%v", body, err)
	}
	waitUntil(t, func() bool { _, _, err := get(t, client, "https://"+address+"/"); return err != nil })
}

func TestListenerSetCertificateChangeAppliesToNextHandshake(t *testing.T) {
	certificates := map[string]tls.Certificate{"stored:one": selfSignedCertificate(t, "one.example.test"), "stored:two": selfSignedCertificate(t, "two.example.test")}
	set := testListenerSet(t, certificates)
	listener := httpListener("secure", "127.0.0.1:0")
	listener.Transport, listener.Certificate = config.HTTPSTransport, "stored:one"
	if err := set.Apply([]config.HTTPListener{listener}); err != nil {
		t.Fatal(err)
	}
	address := set.Addrs()["secure"]
	presented := func() string {
		connection, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec -- inspecting the presented certificate
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		return connection.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	if got := presented(); got != "one.example.test" {
		t.Fatalf("initial certificate %q", got)
	}
	listener.Certificate = "stored:two"
	if err := set.Apply([]config.HTTPListener{listener}); err != nil {
		t.Fatal(err)
	}
	if set.Addrs()["secure"] != address {
		t.Fatal("certificate change rebound the listener")
	}
	if got := presented(); got != "two.example.test" {
		t.Fatalf("certificate after change %q", got)
	}
}

func TestListenerSetFailedApplyKeepsRunningListeners(t *testing.T) {
	set := testListenerSet(t, map[string]tls.Certificate{})
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	address := freePort(t)
	main := httpListener("main", address)
	if err := set.Apply([]config.HTTPListener{main}); err != nil {
		t.Fatal(err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	for name, change := range map[string][]config.HTTPListener{
		"busy address":        {main, httpListener("extra", occupied.Addr().String())},
		"move to busy":        {httpListener("main", occupied.Addr().String())},
		"missing certificate": {{ID: "main", Enabled: true, Transport: config.HTTPSTransport, Address: address, Certificate: "stored:missing", Services: []string{"web"}}},
	} {
		if err := set.Apply(change); err == nil {
			t.Fatalf("%s: apply succeeded", name)
		}
		if addrs := set.Addrs(); len(addrs) != 1 || addrs["main"] != address {
			t.Fatalf("%s: running listeners changed to %v", name, addrs)
		}
		if _, body, err := get(t, client, "http://"+address+"/"); err != nil || body != "main" {
			t.Fatalf("%s: previous listener stopped serving: body=%q err=%v", name, body, err)
		}
	}
}

func TestListenerSetRetiresWithoutDroppingInFlightRequest(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	set := NewListenerSet(func(config.HTTPListener) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			once.Do(func() { close(started) })
			<-release
			_, _ = io.WriteString(w, "done")
		})
	}, nil, Timeouts{ReadHeader: time.Second, Idle: time.Second})
	set.Serve()
	t.Cleanup(set.Close)
	if err := set.Apply([]config.HTTPListener{httpListener("main", "127.0.0.1:0")}); err != nil {
		t.Fatal(err)
	}
	address := set.Addrs()["main"]
	result := make(chan string, 1)
	go func() {
		_, body, err := get(t, &http.Client{Timeout: 5 * time.Second}, "http://"+address+"/")
		if err != nil {
			body = err.Error()
		}
		result <- body
	}()
	<-started
	if err := set.Apply(nil); err != nil {
		t.Fatal(err)
	}
	close(release)
	if body := <-result; !strings.Contains(body, "done") {
		t.Fatalf("in-flight request on retired listener: %q", body)
	}
}

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
