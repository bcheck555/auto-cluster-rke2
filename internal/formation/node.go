package formation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/hostagent"
	"auto-cluster-rke2/internal/state"
)

type Runtime interface {
	hostagent.Runtime
	Existing(context.Context) (bool, error)
	EnsureNetwork(context.Context, hostagent.Plan) error
}
type EnrollmentClient interface {
	Enroll(context.Context, Peer, Member) (Credentials, error)
	Complete(context.Context, Peer, Member) (Member, error)
}

type Node struct {
	Settings          Settings
	Auth              Auth
	Journal           state.Journal
	Runtime           Runtime
	Find              func(context.Context) ([]Peer, error)
	Client            EnrollmentClient
	Backend           func(State) Backend
	UpdateProxies     func([]Peer)
	StartedAt         time.Time
	PublicCertificate func() []byte
	Gate              func(context.Context, State, []Peer) error
	mu                sync.RWMutex
	current           State
	serving           bool
	operation         state.Operation
}

func (n *Node) Current() Peer {
	n.mu.RLock()
	defer n.mu.RUnlock()
	p := n.Auth.Self
	if n.PublicCertificate != nil {
		p.Certificate = n.PublicCertificate()
	}
	p.ClusterID = n.current.ClusterID
	p.Phase = n.current.Phase
	p.Role = n.current.Role
	p.Serving = n.serving
	return p
}
func (n *Node) CurrentBackend() Backend {
	n.mu.RLock()
	s := n.current
	n.mu.RUnlock()
	if n.Backend == nil {
		return nil
	}
	return n.Backend(s)
}

func (n *Node) restore(ctx context.Context) error {
	op, err := n.Journal.Get(ctx, "formation")
	if errors.Is(err, state.ErrNotFound) {
		n.current = State{Phase: "Discovering", NodeName: "rke2-" + n.Auth.Self.ID[:16], Address: n.Auth.Self.Address, Interface: n.Settings.Interface, Policy: n.Settings.Policy(), Deployment: n.Auth.Deployment}
		return nil
	}
	if err != nil {
		return err
	}
	var s State
	if durable.Decode([]byte(op.Details), &s) != nil || op.Kind != "self-forming" || op.HostID != n.Auth.Self.ID || op.ClusterID != s.ClusterID || op.Phase != s.Phase || s.Revision != op.Revision || s.Deployment != n.Auth.Deployment || s.Policy != n.Settings.Policy() || s.Address != n.Auth.Self.Address || s.Interface != n.Settings.Interface || s.NodeName != incarnationName(n.Auth.Self.ID, s.Generation) {
		return ErrConflict
	}
	allowed := map[string]bool{"Selected": true, "Credentialed": true, "Configured": true, "Starting": true, "Healthy": true}
	if !allowed[s.Phase] || (s.Mode != "bootstrap" && s.Mode != "join") || (s.Mode == "bootstrap" && s.Role != "server") || (s.Role != "" && s.Role != "server" && s.Role != "agent") {
		return ErrConflict
	}
	if s.Phase != "Selected" && n.plan(s).Validate() != nil {
		return ErrConflict
	}
	n.current = s
	n.operation = op
	return nil
}

// Restore runs before listeners start, so a returning node never advertises
// itself as a fresh node while its persistent cluster identity is loading.
func (n *Node) Restore(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.Auth.Self.ID) != 64 || n.Settings.Validate() != nil || n.Journal == nil {
		return ErrInvalid
	}
	return n.restore(ctx)
}

func (n *Node) save(ctx context.Context, s State) error {
	next := n.operation
	if next.Revision == 0 {
		next = state.Operation{ID: "formation", ClusterID: s.ClusterID, HostID: n.Auth.Self.ID, Kind: "self-forming"}
	}
	s.Revision = next.Revision + 1
	next.Revision = s.Revision
	next.Phase = s.Phase
	next.UpdatedAt = time.Now().UTC()
	data, _ := json.Marshal(s)
	next.Details = string(data)
	if err := n.Journal.CompareAndSwap(ctx, n.operation.Revision, next); err != nil {
		return err
	}
	n.operation = next
	n.mu.Lock()
	n.current = s
	n.mu.Unlock()
	return nil
}

func (n *Node) plan(s State) hostagent.Plan {
	credentials := filepath.Join(n.Settings.StateDirectory, "credentials")
	p := hostagent.Plan{ClusterID: s.ClusterID, PolicyDigest: s.Policy, Mode: s.Mode, Role: s.Role, NodeName: s.NodeName, NodeIP: s.Address, Interface: s.Interface, RegistrationURL: s.RegistrationURL, APIURL: "https://" + API, TokenFile: filepath.Join(credentials, "rke2-token"), CoreImageSHA256: n.Settings.CoreImageSHA256, FlannelImageSHA256: n.Settings.FlannelImageSHA256, CoreDNSSHA256: n.Settings.CoreDNSSHA256, MinVotingServers: 1}
	p.Generation = s.Generation
	if s.Role == "server" {
		p.AgentTokenFile = filepath.Join(credentials, "agent-token")
	}
	return p
}

func (n *Node) member(s State) Member {
	return Member{ID: n.Auth.Self.ID, PublicKey: n.Auth.Self.PublicKey, NodeName: s.NodeName, Address: s.Address, RequestID: incarnationRequest(n.Auth.Self.ID, s.Generation), Role: s.Role, Generation: s.Generation, Complete: s.Phase == "Healthy", NodeUID: s.Evidence.NodeUID, EtcdMemberID: s.Evidence.EtcdMemberID}
}

func clusterID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

func createToken(path string) error {
	if _, err := hostagent.ReadFile(path, true, 4096); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	return hostagent.WritePrivateFile(path, []byte(hex.EncodeToString(token[:])+"\n"))
}

func (n *Node) credentials(ctx context.Context, s *State, servers []Peer) error {
	if s.Mode == "bootstrap" {
		p := n.plan(*s)
		if err := createToken(p.TokenFile); err != nil {
			return err
		}
		if err := createToken(p.AgentTokenFile); err != nil {
			return err
		}
		return nil
	}
	for _, peer := range servers {
		credentials, err := n.Client.Enroll(ctx, peer, n.member(*s))
		if err != nil {
			continue
		}
		if credentials.Member.Complete {
			return ErrConflict
		} // no unjournaled reinstallation of an existing member
		if err := validateCredentials(credentials, n.Auth.Self); err != nil {
			return err
		}
		s.Role = credentials.Member.Role
		// RKE2 caches this port against discovered server IPs. Keep its native
		// port so its own client load balancer can reconnect after reboot.
		s.RegistrationURL = "https://" + net.JoinHostPort(peer.Address, "9345")
		p := n.plan(*s)
		token := credentials.AgentToken
		if s.Role == "server" {
			token = credentials.ServerToken
		}
		if len(token) < 100 || len(credentials.ServerCA) == 0 || (s.Role == "agent" && (credentials.ServerToken != "" || len(credentials.ReaderCertificate) == 0)) {
			return ErrInvalid
		}
		if err := hostagent.WritePrivateFile(p.TokenFile, []byte(token+"\n")); err != nil {
			return err
		}
		if s.Role == "server" {
			// RKE2's server agent-token-file takes the password, whereas joining
			// workers use the complete CA-pinned node: token.
			if err := hostagent.WritePrivateFile(p.AgentTokenFile, []byte(credentials.AgentToken[74:]+"\n")); err != nil {
				return err
			}
		}
		if err := hostagent.WritePrivateFile(filepath.Join(n.Settings.StateDirectory, "credentials/server-ca.crt"), credentials.ServerCA); err != nil {
			return err
		}
		if s.Role == "agent" {
			if err := hostagent.WritePrivateFile(filepath.Join(n.Settings.StateDirectory, "credentials/reader.crt"), credentials.ReaderCertificate); err != nil {
				return err
			}
		}
		return nil
	}
	return ErrWaiting
}

// Step resumes one immutable initial role and cluster. It never promotes,
// deletes data, resets quorum, or bootstraps a previously selected/joined node.
func (n *Node) Step(ctx context.Context) error {
	if n.Runtime == nil || n.Find == nil || n.Client == nil || n.Backend == nil || n.Settings.Validate() != nil {
		return ErrInvalid
	}
	err := durable.WithLock(ctx, filepath.Join(n.Settings.StateDirectory, "execution"), func(*durable.Directory) error { return n.step(ctx) })
	if err != nil {
		n.mu.Lock()
		n.serving = false
		n.mu.Unlock()
	}
	return err
}

func (n *Node) step(ctx context.Context) error {
	n.mu.Lock()
	err := n.restore(ctx)
	s := n.current
	n.mu.Unlock()
	if err != nil {
		return err
	}
	peers, err := n.Find(ctx)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if peer.Policy != s.Policy {
			return ErrConflict
		}
	}
	choice, selectionErr := Select(n.Auth.Self.ID, s.ClusterID, peers)
	if errors.Is(selectionErr, ErrConflict) {
		n.mu.Lock()
		n.serving = false
		n.mu.Unlock()
		return ErrConflict
	}
	servers := choice.Servers
	if len(servers) == 0 {
		servers = s.Servers
	}
	if n.UpdateProxies != nil {
		n.UpdateProxies(servers)
	}
	if n.Gate != nil && s.ClusterID != "" && s.Phase == "Healthy" {
		if err := n.Gate(ctx, s, servers); err != nil {
			return err
		}
	}
	if s.ClusterID == "" {
		if selectionErr != nil {
			return selectionErr
		}
		existing, err := n.Runtime.Existing(ctx)
		if err != nil {
			return err
		}
		if existing {
			return ErrConflict
		}
		if entries, err := os.ReadDir(filepath.Join(n.Settings.StateDirectory, "credentials")); err == nil && len(entries) > 0 {
			return ErrConflict
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ErrConflict
		}
		if choice.Bootstrap {
			if n.StartedAt.IsZero() || time.Since(n.StartedAt) < time.Duration(n.Settings.BootstrapDelaySeconds)*time.Second {
				return ErrWaiting
			}
			s.ClusterID, err = clusterID()
			if err != nil {
				return err
			}
			s.Mode = "bootstrap"
			s.Role = "server"
			s.RegistrationURL = "https://" + net.JoinHostPort(s.Address, "9345")
		} else {
			s.ClusterID = choice.ClusterID
			s.Mode = "join"
		}
		s.Servers = servers
		s.Phase = "Selected"
		if err := n.save(ctx, s); err != nil {
			return err
		}
	}
	if digest(servers) != digest(s.Servers) {
		s.Servers = servers
		if err := n.save(ctx, s); err != nil {
			return err
		}
	}
	if s.Phase == "Selected" {
		if err := n.credentials(ctx, &s, servers); err != nil {
			return err
		}
		s.Phase = "Credentialed"
		if err := n.save(ctx, s); err != nil {
			return err
		}
	}
	p := n.plan(s)
	if p.Validate() != nil {
		return ErrConflict
	}
	snapshot, err := n.Runtime.Inspect(ctx, p, n.Auth.Self.ID)
	if err != nil {
		return err
	}
	if s.Phase == "Credentialed" {
		if (snapshot.HasData && !s.Transition) || snapshot.Running {
			return ErrConflict
		}
		if err := n.Runtime.Prepare(ctx, p, n.Auth.Self.ID); err != nil {
			return err
		}
		s.CredentialDigest = snapshot.CredentialDigest
		s.Phase = "Configured"
		if err := n.save(ctx, s); err != nil {
			return err
		}
	}
	snapshot, err = n.Runtime.Inspect(ctx, p, n.Auth.Self.ID)
	if err != nil {
		return err
	}
	if !snapshot.ConfigMatches || snapshot.CredentialDigest != s.CredentialDigest {
		return ErrConflict
	}
	if s.Phase == "Healthy" && s.Role == "agent" {
		if err := n.renewReader(ctx, s, servers); err != nil {
			return err
		}
	}
	if s.Phase == "Configured" {
		if (snapshot.HasData && !s.Transition) || snapshot.Running {
			return ErrConflict
		}
		s.Phase = "Starting"
		if err := n.save(ctx, s); err != nil {
			return err
		}
	}
	if s.Phase == "Healthy" && (!snapshot.HasData || !snapshot.DataIntact) {
		return ErrConflict
	}
	if err := n.Runtime.EnsureNetwork(ctx, p); err != nil {
		return err
	}
	if !snapshot.Running {
		if err := n.Runtime.Start(ctx, s.Role); err != nil {
			return err
		}
	}
	evidence, err := n.Runtime.Check(ctx, p, n.Auth.Self.ID, s.Mode == "bootstrap" && s.Phase == "Starting")
	if err != nil {
		n.mu.Lock()
		n.serving = false
		n.mu.Unlock()
		return err
	}
	if evidence.NodeUID == "" || (s.Role == "server" && (evidence.EtcdClusterID == "" || evidence.EtcdMemberID == "")) {
		return ErrWaiting
	}
	if s.Evidence.NodeUID != "" && (s.Evidence.NodeUID != evidence.NodeUID || s.Evidence.EtcdClusterID != evidence.EtcdClusterID || s.Evidence.EtcdMemberID != evidence.EtcdMemberID) {
		return ErrConflict
	}
	member := n.member(s)
	if s.Mode == "bootstrap" && s.Phase == "Starting" {
		member.Complete = true
		member.NodeUID = evidence.NodeUID
		member.EtcdMemberID = evidence.EtcdMemberID
		if err := n.Backend(s).Init(ctx, member); err != nil {
			return err
		}
	} else if s.Role == "server" {
		registered, err := n.Backend(s).Complete(ctx, member)
		if err != nil {
			return err
		}
		if registered.NodeUID != evidence.NodeUID || registered.EtcdMemberID != evidence.EtcdMemberID {
			return ErrConflict
		}
	} else {
		complete := false
		for _, server := range servers {
			registered, err := n.Client.Complete(ctx, server, member)
			if err == nil {
				if registered.NodeUID != evidence.NodeUID {
					return ErrConflict
				}
				complete = true
				break
			}
		}
		if !complete {
			return ErrWaiting
		}
	}
	if s.Phase != "Healthy" {
		s.Phase = "Healthy"
		s.Evidence = evidence
		if err := n.save(ctx, s); err != nil {
			return err
		}
	}
	n.mu.Lock()
	n.serving = s.Role == "server"
	n.mu.Unlock()
	if s.Role == "server" && n.UpdateProxies != nil {
		self := n.Current()
		servers = append(servers, self)
		n.UpdateProxies(servers)
	}
	return nil
}

func Deployment(secret []byte) string {
	sum := sha256.Sum256(append([]byte("autonomous-rke2/deployment/v1\x00"), secret...))
	return hex.EncodeToString(sum[:])
}
