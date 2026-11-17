package pop3

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/metrics"
)

func TestActiveConnectionsAggregateAcrossServersAndReturnToZero(t *testing.T) {
	gauge := metrics.NewConnectionGauge(nil, "pop3_active_connections")
	ctx, cancel := context.WithCancel(t.Context())
	servers := []*Server{
		New(&Config{ServerName: "test", Connections: gauge}),
		New(&Config{ServerName: "test", Connections: gauge}),
	}
	connections := make([]net.Conn, 0, len(servers))
	for _, server := range servers {
		listener, err := server.Listen("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go server.Accept(ctx, listener)
		connection, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	waitPOP3Connections(t, gauge, 2)
	for _, connection := range connections {
		_ = connection.Close()
	}
	waitPOP3Connections(t, gauge, 0)
	cancel()
	for _, server := range servers {
		_ = server.Close()
	}
}

func waitPOP3Connections(t *testing.T, gauge *metrics.ConnectionGauge, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gauge.Active() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active connections = %d, want %d", gauge.Active(), want)
}

func TestIdleConnectionClosedAfterIdleTimeout(t *testing.T) {
	addr, _, cleanup := makeTestServerWithConfig(t, setupTestStore(t), func(cfg *Config) {
		cfg.IdleTimeout = 150 * time.Millisecond
	})
	defer cleanup()
	client := newPop3Client(t, addr)
	defer client.close()

	// Each command re-arms the autologout timer.
	for range 3 {
		time.Sleep(75 * time.Millisecond)
		if resp, err := client.cmd("NOOP"); err != nil || !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("NOOP before idle timeout = %q, %v", resp, err)
		}
	}

	_ = client.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if line, err := client.readLine(); err == nil {
		t.Fatalf("idle connection still open, read %q", line)
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("server did not close the idle connection")
	}
}

func TestConnectionLimitCapsConcurrentConnectionsPerIP(t *testing.T) {
	addr, _, cleanup := makeTestServerWithConfig(t, setupTestStore(t), func(cfg *Config) {
		cfg.RateLimitConnections = true
		cfg.ConnectionPolicy.MaxPerIP = 3
	})
	defer cleanup()
	dial := func() (net.Conn, string) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, _ := bufio.NewReader(conn).ReadString('\n')
		return conn, line
	}
	var open []net.Conn
	for i := range 3 {
		conn, greeting := dial()
		if !strings.HasPrefix(greeting, "+OK") {
			t.Fatalf("connection %d below the cap: greeting %q", i+1, greeting)
		}
		open = append(open, conn)
	}
	refused, line := dial()
	_ = refused.Close()
	if !strings.HasPrefix(line, "-ERR [SYS/TEMP] Too many connections") {
		t.Fatalf("connection above the cap: %q, want a SYS/TEMP refusal", line)
	}
	_ = open[0].Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, greeting := dial()
		_ = conn.Close()
		if strings.HasPrefix(greeting, "+OK") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("closing a connection did not free a slot: %q", greeting)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, conn := range open[1:] {
		_ = conn.Close()
	}
}
