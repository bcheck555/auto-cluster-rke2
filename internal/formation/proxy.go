package formation

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// Proxy is a node-local TCP passthrough. RKE2/observer TLS verifies the cluster
// CA end to end. Discovery updates peers; no external VIP or balancer is needed.
type Proxy struct {
	mu        sync.RWMutex
	addresses []string
	Port      string
	next      uint64
}

func (p *Proxy) Update(peers []Peer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addresses = nil
	for _, peer := range peers {
		p.addresses = append(p.addresses, net.JoinHostPort(peer.Address, p.Port))
	}
}

func (p *Proxy) Serve(ctx context.Context, listen string) error {
	l, err := net.Listen("tcp4", listen)
	if err != nil {
		return ErrWaiting
	}
	return p.serve(ctx, l)
}

func (p *Proxy) serve(ctx context.Context, l net.Listener) error {
	defer l.Close()
	go func() { <-ctx.Done(); _ = l.Close() }()
	slots := make(chan struct{}, 256)
	for {
		incoming, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrWaiting
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); p.forward(ctx, incoming) }()
		default:
			_ = incoming.Close()
		}
	}
}

func (p *Proxy) forward(ctx context.Context, incoming net.Conn) {
	defer incoming.Close()
	p.mu.Lock()
	addresses := append([]string(nil), p.addresses...)
	if len(addresses) > 0 {
		offset := int(p.next % uint64(len(addresses)))
		p.next++
		addresses = append(addresses[offset:], addresses[:offset]...)
	}
	p.mu.Unlock()
	for _, address := range addresses {
		outgoing, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", address)
		if err != nil {
			continue
		}
		defer outgoing.Close()
		done := make(chan struct{}, 1)
		go func() {
			_, _ = io.Copy(outgoing, incoming)
			if tcp, ok := outgoing.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			done <- struct{}{}
		}()
		finished := make(chan struct{}, 1)
		go func() {
			_, _ = io.Copy(incoming, outgoing)
			if tcp, ok := incoming.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			finished <- struct{}{}
		}()
		select {
		case <-ctx.Done():
		case <-done:
		case <-finished:
		}
		return
	}
}
