// Package hostagent implements initial, authorized RKE2 host convergence.
// Membership replacement, promotion, and data-directory repair are excluded.
package hostagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"regexp"

	"autonomous-rke2/internal/bootstrap"
)

const RKE2Version = "v1.37.1+rke2r1"
const RKE2RPM = "1.37.1~rke2r1-0.el9.x86_64"
const PolicyRPM = "0.23-1.el9.noarch"

var (
	ErrInvalid   = errors.New("invalid host plan")
	ErrWaiting   = errors.New("host convergence waiting for a prerequisite")
	ErrReconcile = errors.New("host state requires operator reconciliation")
)

type Plan struct {
	ClusterID          string
	PolicyDigest       string
	Mode               string // explicitly bootstrap or join; never inferred from reachability
	Role               string // must equal the signed enrollment role
	NodeName           string
	NodeIP             string
	Interface          string
	RegistrationURL    string // discovered native supervisor origin, port 9345
	APIURL             string // local health proxy or legacy stable API origin
	TokenFile          string
	AgentTokenFile     string // bootstrap server's separate worker secret
	CoreImageSHA256    string
	FlannelImageSHA256 string
	CoreDNSSHA256      string
	MinVotingServers   int
}

var nodePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func hashValid(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && len(s) == 64
}

func (p Plan) Validate() error {
	if !uuidPattern.MatchString(p.ClusterID) || !hashValid(p.PolicyDigest) || (p.Mode != "bootstrap" && p.Mode != "join") || (p.Role != bootstrap.RoleServer && p.Role != bootstrap.RoleAgent) || (p.Mode == "bootstrap" && p.Role != bootstrap.RoleServer) || !nodePattern.MatchString(p.NodeName) || !ifacePattern.MatchString(p.Interface) {
		return ErrInvalid
	}
	ip := net.ParseIP(p.NodeIP)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return ErrInvalid
	}
	if !bootstrap.ValidEndpoint(p.RegistrationURL) || !bootstrap.ValidEndpoint(p.APIURL) {
		return ErrInvalid
	}
	r, _ := url.Parse(p.RegistrationURL)
	a, _ := url.Parse(p.APIURL)
	registrationIP := net.ParseIP(r.Hostname())
	local := a.Hostname() == "127.0.0.1" && a.Port() == "7443" && r.Port() == "9345" && registrationIP != nil && registrationIP.To4() != nil && !registrationIP.IsLoopback() && !registrationIP.IsUnspecified() && !registrationIP.IsMulticast()
	if !local && (r.Port() != "9345" || a.Port() != "6443" || r.Hostname() != a.Hostname()) {
		return ErrInvalid
	}
	for _, path := range []string{p.TokenFile, p.AgentTokenFile} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return ErrInvalid
		}
	}
	if p.TokenFile == "" || (p.Role == bootstrap.RoleServer && (p.AgentTokenFile == "" || p.AgentTokenFile == p.TokenFile)) || (p.Role == bootstrap.RoleAgent && p.AgentTokenFile != "") || !hashValid(p.CoreImageSHA256) || !hashValid(p.FlannelImageSHA256) || !hashValid(p.CoreDNSSHA256) || p.MinVotingServers < 1 || p.MinVotingServers > 3 {
		return ErrInvalid
	}
	return nil
}

func fingerprint(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// RenderConfig contains paths to protected credentials, never token contents.
// JSON is valid YAML and is accepted by RKE2's YAML configuration reader.
func (p Plan) RenderConfig(host string) ([]byte, error) {
	if p.Validate() != nil || !hashValid(host) {
		return nil, ErrInvalid
	}
	config := map[string]any{"selinux": true, "node-name": p.NodeName, "node-ip": p.NodeIP, "token-file": p.TokenFile, "node-label": []string{"autonomous-rke2.io/host-id=" + host[:32], "autonomous-rke2.io/cluster-id=" + p.ClusterID}}
	config["disable-default-registry-endpoint"] = true
	if p.Mode == "join" {
		config["server"] = p.RegistrationURL
	}
	if p.Role == bootstrap.RoleServer {
		u, _ := url.Parse(p.APIURL)
		config["cni"] = "flannel"
		config["advertise-address"] = p.NodeIP
		config["cluster-cidr"] = "10.42.0.0/16"
		config["service-cidr"] = "10.43.0.0/16"
		config["tls-san"] = []string{u.Hostname()}
		config["tls-san-security"] = true
		config["write-kubeconfig-mode"] = "0600"
		config["agent-token-file"] = p.AgentTokenFile
	}
	return json.MarshalIndent(config, "", "  ")
}
