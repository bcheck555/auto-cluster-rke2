// Package formation implements first-node-first, node-resident cluster formation.
// Empty discovery is meaningful only under the documented reachable-L2 bootstrap
// assumption; it is not proof that a partitioned cluster does not exist.
package formation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"auto-cluster-rke2/internal/hostagent"
)

var (
	ErrWaiting  = errors.New("formation waiting for a reachable cluster or prerequisite")
	ErrConflict = errors.New("formation identity or membership conflict")
	ErrInvalid  = errors.New("invalid formation input")
)

const Group = "239.192.42.42:9444"
const Port = 9443
const API = "127.0.0.1:7443"

type Settings struct {
	StateDirectory        string
	SecretFile            string
	Interface             string
	CoreImageSHA256       string
	FlannelImageSHA256    string
	CoreDNSSHA256         string
	BootstrapDelaySeconds int
}

func (s *Settings) Defaults() {
	if s.StateDirectory == "" {
		s.StateDirectory = "/var/lib/autonomous-rke2"
	}
	if s.SecretFile == "" {
		s.SecretFile = "/etc/autonomous-rke2/enrollment-secret"
	}
	if s.BootstrapDelaySeconds == 0 {
		s.BootstrapDelaySeconds = 30
	}
}

func (s Settings) Validate() error {
	for _, p := range []string{s.StateDirectory, s.SecretFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return ErrInvalid
		}
	}
	for _, h := range []string{s.CoreImageSHA256, s.FlannelImageSHA256, s.CoreDNSSHA256} {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 || len(h) != 64 {
			return ErrInvalid
		}
	}
	if s.BootstrapDelaySeconds < 5 || s.BootstrapDelaySeconds > 300 {
		return ErrInvalid
	}
	return nil
}

func (s Settings) Policy() string {
	return digest(struct {
		Servers                     int
		Version, Core, Flannel, DNS string
		Formation                   string
	}{7, hostagent.RKE2Version, s.CoreImageSHA256, s.FlannelImageSHA256, s.CoreDNSSHA256, HealingCapability})
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Peer struct {
	ID          string
	PublicKey   []byte
	Address     string
	Certificate []byte
	Policy      string
	ClusterID   string
	Phase       string
	Role        string
	Serving     bool
}

type Choice struct {
	Bootstrap bool
	ClusterID string
	Servers   []Peer
}

func Select(self, known string, peers []Peer) (Choice, error) {
	clusters := map[string]bool{}
	if known != "" {
		clusters[known] = true
	}
	for _, p := range peers {
		if p.ClusterID != "" {
			clusters[p.ClusterID] = true
		}
	}
	if len(clusters) > 1 {
		return Choice{}, ErrConflict
	}
	if len(clusters) == 1 {
		var cluster string
		for id := range clusters {
			cluster = id
		}
		var servers []Peer
		for _, p := range peers {
			if p.ClusterID == cluster && p.Role == "server" && p.Serving {
				servers = append(servers, p)
			}
		}
		sort.Slice(servers, func(i, j int) bool { return servers[i].ID < servers[j].ID })
		if len(servers) == 0 {
			return Choice{ClusterID: cluster}, ErrWaiting
		}
		return Choice{ClusterID: cluster, Servers: servers}, nil
	}
	for _, p := range peers {
		if p.ID < self {
			return Choice{}, ErrWaiting
		}
	}
	return Choice{Bootstrap: true}, nil
}

type Member struct {
	ID           string
	PublicKey    []byte
	NodeName     string
	Address      string
	RequestID    string
	Role         string
	Complete     bool
	NodeUID      string
	EtcdMemberID string
	Retiring     bool
	Generation   uint64
	Index        int
	PodCIDR      string
	PodCIDRs     []string
}

type Credentials struct {
	Member            Member
	ServerToken       string
	AgentToken        string
	ServerCA          []byte
	ReaderCertificate []byte
}

type State struct {
	Phase            string
	ClusterID        string
	Mode             string
	Role             string
	NodeName         string
	Address          string
	Interface        string
	Policy           string
	Deployment       string
	CredentialDigest string
	RegistrationURL  string
	Evidence         hostagent.Evidence
	Revision         uint64
	Servers          []Peer
	Generation       uint64
	Transition       bool
}

func network(name string) (string, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", ErrWaiting
	}
	return selectNetwork(name, interfaces, func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() })
}

func selectNetwork(name string, interfaces []net.Interface, addressesFor func(net.Interface) ([]net.Addr, error)) (string, string, error) {
	var candidates [][2]string
	for _, iface := range interfaces {
		// RKE2 creates these interfaces after initial boot. They must not make
		// automatic uplink selection ambiguous on health checks or agent restart.
		if managedInterface(iface.Name) {
			continue
		}
		if name != "" && iface.Name != name {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		addresses, err := addressesFor(iface)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				candidates = append(candidates, [2]string{iface.Name, ip.String()})
			}
		}
	}
	if len(candidates) != 1 {
		return "", "", ErrWaiting
	}
	return candidates[0][0], candidates[0][1], nil
}

func managedInterface(name string) bool {
	return strings.HasPrefix(name, "flannel") || strings.HasPrefix(name, "cni") || strings.HasPrefix(name, "veth")
}
