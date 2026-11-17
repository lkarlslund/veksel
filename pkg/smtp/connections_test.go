package smtp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/metrics"
)

func TestActiveConnectionsAggregateAcrossServersAndReturnToZero(t *testing.T) {
	gauge := metrics.NewConnectionGauge(nil, "smtp_active_connections")
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
	waitSMTPConnections(t, gauge, 2)
	for _, connection := range connections {
		_ = connection.Close()
	}
	waitSMTPConnections(t, gauge, 0)
	cancel()
	for _, server := range servers {
		_ = server.Close()
	}
}

func waitSMTPConnections(t *testing.T, gauge *metrics.ConnectionGauge, want int64) {
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
