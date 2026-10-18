package formation

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestLocalProxyTriesAnotherServerAndClosesOnCancellation(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	dead, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddress := dead.Addr().String()
	dead.Close()
	go func() {
		connection, err := backend.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()
	proxy := &Proxy{addresses: []string{deadAddress, backend.Addr().String()}}
	incoming, client := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { proxy.forward(ctx, incoming); close(done) }()
	want := []byte("end-to-end TLS bytes")
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(want))
	if _, err := io.ReadFull(client, buffer); err != nil || string(buffer) != string(want) {
		t.Fatal("proxy failed backend failover", string(buffer), err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not stop")
	}
}
