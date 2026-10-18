package formation

import (
	"context"
	"encoding/json"
	"net"
	"syscall"
	"time"
)

// Discovery is deployment-authenticated IPv4 multicast, scoped to the selected
// interface. It uses bounded JSON datagrams, not mDNS or untrusted endpoint trust.
type Discovery struct {
	Auth      Auth
	Interface string
	Current   func() Peer
	Ready     chan<- struct{}
}

func (d Discovery) Serve(ctx context.Context) error {
	iface, err := net.InterfaceByName(d.Interface)
	if err != nil {
		return ErrWaiting
	}
	group, _ := net.ResolveUDPAddr("udp4", Group)
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		return ErrWaiting
	}
	defer conn.Close()
	if d.Ready != nil {
		close(d.Ready)
	}
	buffer := make([]byte, 4097)
	for {
		if ctx.Err() != nil {
			return nil
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return ErrWaiting
		}
		if n > 4096 {
			continue
		}
		var m Message
		if json.Unmarshal(buffer[:n], &m) != nil || m.Kind != "query" || d.Auth.Verify(m) != nil || m.Peer.Address != source.IP.String() || m.Peer.ID == d.Auth.Self.ID {
			continue
		}
		auth := d.Auth
		auth.Self = d.Current()
		reply, err := auth.Sign(ctx, Message{Kind: "reply", Nonce: m.Nonce})
		if err != nil {
			continue
		}
		data, _ := json.Marshal(reply)
		if len(data) <= 4096 {
			_, _ = conn.WriteToUDP(data, source)
		}
	}
}

func (d Discovery) Find(ctx context.Context) ([]Peer, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(d.Auth.Self.Address)})
	if err != nil {
		return nil, ErrWaiting
	}
	defer conn.Close()
	// Isolated L2 may lack a default route. Select the outgoing multicast
	// interface explicitly; TTL 1 keeps probes on the local segment.
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, ErrWaiting
	}
	var optionErr error
	ip := net.ParseIP(d.Auth.Self.Address).To4()
	if ip == nil {
		return nil, ErrInvalid
	}
	var outgoing [4]byte
	copy(outgoing[:], ip)
	if err := raw.Control(func(fd uintptr) {
		optionErr = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, outgoing)
		if optionErr == nil {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 1)
		}
	}); err != nil || optionErr != nil {
		return nil, ErrWaiting
	}
	challenge, err := nonce()
	if err != nil {
		return nil, err
	}
	auth := d.Auth
	auth.Self = d.Current()
	m, err := auth.Sign(ctx, Message{Kind: "query", Nonce: challenge})
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(m)
	group, _ := net.ResolveUDPAddr("udp4", Group)
	peers := map[string]Peer{}
	buffer := make([]byte, 4097)
	for range 3 {
		if _, err := conn.WriteToUDP(data, group); err != nil {
			return nil, ErrWaiting
		}
		deadline := time.Now().Add(time.Second)
		if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
			deadline = outer
		}
		_ = conn.SetReadDeadline(deadline)
		for {
			if time.Now().After(deadline) || ctx.Err() != nil {
				break
			}
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					break
				}
				return nil, ErrWaiting
			}
			var reply Message
			if n > 4096 || json.Unmarshal(buffer[:n], &reply) != nil || reply.Kind != "reply" || reply.Nonce != challenge || d.Auth.Verify(reply) != nil || reply.Peer.Address != source.IP.String() || reply.Peer.ID == d.Auth.Self.ID {
				continue
			}
			if _, err := PeerCertificate(reply.Peer); err != nil {
				continue
			}
			if len(peers) >= 64 {
				if _, ok := peers[reply.Peer.ID]; !ok {
					return nil, ErrConflict
				}
			}
			peers[reply.Peer.ID] = reply.Peer
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	result := make([]Peer, 0, len(peers))
	for _, peer := range peers {
		result = append(result, peer)
	}
	return result, nil
}
