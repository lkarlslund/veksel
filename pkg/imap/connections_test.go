package imap

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/metrics"
)

func TestActiveConnectionsAggregateAcrossServersAndReturnToZero(t *testing.T) {
	testIMAPActiveConnections(t, func(gauge *metrics.ConnectionGauge) *Server {
		return New(&Config{ServerName: "test", Connections: gauge})
	})
}

func testIMAPActiveConnections(t *testing.T, create func(*metrics.ConnectionGauge) *Server) {
	t.Helper()
	gauge := metrics.NewConnectionGauge(nil, "imap_active_connections")
	ctx, cancel := context.WithCancel(t.Context())
	servers := []*Server{create(gauge), create(gauge)}
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
	waitIMAPConnections(t, gauge, 2)
	for _, connection := range connections {
		_ = connection.Close()
	}
	waitIMAPConnections(t, gauge, 0)
	cancel()
	for _, server := range servers {
		_ = server.Close()
	}
}

func waitIMAPConnections(t *testing.T, gauge *metrics.ConnectionGauge, want int64) {
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
