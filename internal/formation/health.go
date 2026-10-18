package formation

import (
	"context"
	"path/filepath"

	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/hostagent"
	"auto-cluster-rke2/internal/identity"
	"auto-cluster-rke2/internal/state"
)

type Health struct {
	ClusterID string
	HostID    string
	Role      string
	Evidence  hostagent.Evidence
}

// CheckHealth independently observes Kubernetes, the immutable cluster marker,
// and (for servers) local etcd. A cached Healthy journal alone is insufficient.
func CheckHealth(ctx context.Context, s Settings) (Health, error) {
	if s.Validate() != nil {
		return Health{}, ErrInvalid
	}
	iface, address, err := network(s.Interface)
	if err != nil {
		return Health{}, err
	}
	s.Interface = iface
	op, err := state.NewFileJournal(filepath.Join(s.StateDirectory, "formation")).Get(ctx, "formation")
	if err != nil {
		return Health{}, err
	}
	var saved State
	if durable.Decode([]byte(op.Details), &saved) != nil || saved.Phase != "Healthy" || saved.Policy != s.Policy() || saved.Address != address || saved.Interface != iface {
		return Health{}, ErrConflict
	}
	signer := identity.NewFileStore(filepath.Join(s.StateDirectory, "identity"))
	if _, err := signer.Sign(ctx, []byte("autonomous-rke2/health/v1")); err != nil {
		return Health{}, ErrConflict
	}
	id, err := signer.LoadOrCreate(ctx)
	if err != nil || id.ID != op.HostID {
		return Health{}, ErrConflict
	}
	n := Node{Settings: s, Auth: Auth{Self: Peer{ID: id.ID, Address: address}, Deployment: saved.Deployment}, Journal: state.NewFileJournal(filepath.Join(s.StateDirectory, "formation"))}
	if err := n.Restore(ctx); err != nil {
		return Health{}, err
	}
	h := &hostagent.HealthChecker{Observer: hostagent.TLSFiles{CA: filepath.Join(s.StateDirectory, "credentials/server-ca.crt"), Cert: filepath.Join(s.StateDirectory, "credentials/reader.crt")}, ObserverSigner: signer}
	runtime := hostagent.NewLinuxRuntime(h)
	plan := n.plan(saved)
	snapshot, err := runtime.Inspect(ctx, plan, id.ID)
	if err != nil {
		return Health{}, err
	}
	if !snapshot.Running || !snapshot.HasData || !snapshot.DataIntact || !snapshot.ConfigMatches || snapshot.CredentialDigest != saved.CredentialDigest {
		return Health{}, ErrConflict
	}
	evidence, err := runtime.Check(ctx, plan, id.ID, false)
	if err != nil {
		return Health{}, err
	}
	if evidence.NodeUID != saved.Evidence.NodeUID || evidence.EtcdClusterID != saved.Evidence.EtcdClusterID || evidence.EtcdMemberID != saved.Evidence.EtcdMemberID {
		return Health{}, ErrConflict
	}
	return Health{ClusterID: op.ClusterID, HostID: op.HostID, Role: saved.Role, Evidence: evidence}, nil
}
