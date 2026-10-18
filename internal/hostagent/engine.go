package hostagent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"auto-cluster-rke2/internal/bootstrap"
	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/identity"
	"auto-cluster-rke2/internal/state"
)

type Remote interface {
	bootstrap.Authority
	bootstrap.Consumer
	bootstrap.StatusReader
}

type Snapshot struct {
	Running          bool
	HasData          bool
	DataIntact       bool
	ConfigMatches    bool
	CredentialDigest string
}
type Evidence struct {
	NodeUID       string
	EtcdClusterID string
	EtcdMemberID  string
	VotingServers int
}

// Runtime contains only initial-install, fixed-service, and read-only health
// operations. There is no stop, delete, reset, member removal, or shell method.
type Runtime interface {
	Inspect(context.Context, Plan, string) (Snapshot, error)
	Prepare(context.Context, Plan, string) error
	Start(context.Context, string) error
	Check(context.Context, Plan, string, bool) (Evidence, error)
}

type Engine struct {
	Plan          Plan
	Identity      identity.Signer
	Journal       state.Journal
	Authority     Remote
	Verifier      bootstrap.Verifier
	Runtime       Runtime
	LockDirectory string
}

type checkpoint struct {
	PlanDigest       string
	CredentialDigest string
	Bootstrap        *bootstrap.BootstrapGrant
	Join             *bootstrap.JoinGrant
	Evidence         Evidence
}

func challenge() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

func (e Engine) status(ctx context.Context, host, op string) (bootstrap.GrantStatus, error) {
	nonce, err := challenge()
	if err != nil {
		return bootstrap.GrantStatus{}, err
	}
	s, err := e.Authority.GrantStatus(ctx, host, op, nonce)
	if err != nil {
		return s, err
	}
	if s.ClusterID != e.Plan.ClusterID {
		return s, ErrReconcile
	}
	if err := e.Verifier.VerifyGrantStatus(ctx, s, host, op, nonce); err != nil {
		return s, err
	}
	return s, nil
}

func (e Engine) Run(ctx context.Context) error {
	if e.Plan.Validate() != nil || e.Identity == nil || e.Journal == nil || e.Authority == nil || e.Runtime == nil {
		return ErrInvalid
	}
	return durable.WithLock(ctx, e.LockDirectory, func(*durable.Directory) error { return e.run(ctx) })
}

func (e Engine) run(ctx context.Context) error {
	id, err := e.Identity.LoadOrCreate(ctx)
	if err != nil {
		return err
	}
	opID := "initial-" + id.ID
	snapshot, err := e.Runtime.Inspect(ctx, e.Plan, id.ID)
	if err != nil {
		return err
	}
	op, err := e.Journal.Get(ctx, opID)
	c := checkpoint{PlanDigest: fingerprint(e.Plan), CredentialDigest: snapshot.CredentialDigest}
	if errors.Is(err, state.ErrNotFound) {
		if snapshot.HasData || snapshot.Running {
			return ErrReconcile
		}
		op = state.Operation{ID: opID, ClusterID: e.Plan.ClusterID, HostID: id.ID, Kind: e.Plan.Mode, Phase: "AwaitingAuthority", Revision: 1, UpdatedAt: time.Now().UTC()}
		data, _ := json.Marshal(c)
		op.Details = string(data)
		if err := e.Journal.CompareAndSwap(ctx, 0, op); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if op.ClusterID != e.Plan.ClusterID || op.HostID != id.ID || op.Kind != e.Plan.Mode || durable.Decode([]byte(op.Details), &c) != nil || c.PlanDigest != fingerprint(e.Plan) || c.CredentialDigest != snapshot.CredentialDigest {
			return ErrReconcile
		}
	}
	advance := func(phase string) error {
		next := op
		next.Phase = phase
		next.Revision++
		next.UpdatedAt = time.Now().UTC()
		data, err := json.Marshal(c)
		if err != nil {
			return ErrInvalid
		}
		next.Details = string(data)
		if err := e.Journal.CompareAndSwap(ctx, op.Revision, next); err != nil {
			return err
		}
		op = next
		return nil
	}
	allowed := map[string]bool{"AwaitingAuthority": true, "Authorized": true, "Consuming": true, "Consumed": true, "Configured": true, "Starting": true, "Healthy": true}
	if !allowed[op.Phase] {
		return ErrReconcile
	}
	if (snapshot.HasData || snapshot.Running) && op.Phase != "Starting" && op.Phase != "Healthy" {
		return ErrReconcile
	}
	s, err := e.status(ctx, id.ID, opID)
	if errors.Is(err, bootstrap.ErrGrantNotFound) && op.Phase == "AwaitingAuthority" {
		req, err := bootstrap.SignRequest(ctx, e.Identity, e.Plan.PolicyDigest, opID)
		if err != nil {
			return err
		}
		if e.Plan.Mode == "bootstrap" {
			g, err := e.Authority.AuthorizeBootstrap(ctx, req)
			if err != nil {
				return err
			}
			c.Bootstrap = &g
		} else {
			g, err := e.Authority.AuthorizeJoin(ctx, e.Plan.ClusterID, req)
			if err != nil {
				return err
			}
			c.Join = &g
		}
		s, err = e.status(ctx, id.ID, opID)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if e.Plan.Mode == "bootstrap" {
		if s.Bootstrap == nil || s.Join != nil || s.Bootstrap.HostID != id.ID || fingerprint(s.Bootstrap.PublicKey) != fingerprint(id.PublicKey) {
			return ErrReconcile
		}
	} else if s.Join == nil || s.Bootstrap != nil || s.Join.Role != e.Plan.Role || s.Join.HostID != id.ID || fingerprint(s.Join.PublicKey) != fingerprint(id.PublicKey) {
		return ErrReconcile
	}
	if op.Phase == "AwaitingAuthority" {
		if s.Consumed {
			return ErrReconcile
		}
		c.Bootstrap = s.Bootstrap
		c.Join = s.Join
		if err := advance("Authorized"); err != nil {
			return err
		}
	} else if fingerprint(c.Bootstrap) != fingerprint(s.Bootstrap) || fingerprint(c.Join) != fingerprint(s.Join) {
		return ErrReconcile
	}
	if op.Phase == "Authorized" {
		if s.Consumed {
			return ErrReconcile
		}
		if err := advance("Consuming"); err != nil {
			return err
		}
	}
	if op.Phase == "Consuming" {
		if !s.Consumed {
			// Even an error may follow a durable consumption. Always resolve it
			// using a fresh signed status before attempting any host mutation.
			if c.Bootstrap != nil {
				_ = e.Authority.ConsumeBootstrapGrant(ctx, *c.Bootstrap)
			} else {
				_ = e.Authority.ConsumeJoinGrant(ctx, *c.Join)
			}
			s, err = e.status(ctx, id.ID, opID)
			if err != nil {
				return err
			}
			if fingerprint(c.Bootstrap) != fingerprint(s.Bootstrap) || fingerprint(c.Join) != fingerprint(s.Join) {
				return ErrReconcile
			}
			if !s.Consumed {
				return ErrWaiting
			}
		}
		if err := advance("Consumed"); err != nil {
			return err
		}
	} else if !s.Consumed {
		return ErrReconcile
	}
	if op.Phase == "Consumed" {
		if err := e.Runtime.Prepare(ctx, e.Plan, id.ID); err != nil {
			return err
		}
		if err := advance("Configured"); err != nil {
			return err
		}
	}
	snapshot, err = e.Runtime.Inspect(ctx, e.Plan, id.ID)
	if err != nil {
		return err
	}
	if !snapshot.ConfigMatches || snapshot.CredentialDigest != c.CredentialDigest {
		return ErrReconcile
	}
	if op.Phase == "Configured" {
		if err := advance("Starting"); err != nil {
			return err
		}
	}
	if !snapshot.Running {
		if op.Phase == "Healthy" {
			return ErrReconcile
		} // returning/stopped members require membership reconciliation
		if err := e.Runtime.Start(ctx, e.Plan.Role); err != nil {
			return err
		}
	}
	evidence, err := e.Runtime.Check(ctx, e.Plan, id.ID, e.Plan.Mode == "bootstrap" && op.Phase == "Starting")
	if err != nil {
		return err
	}
	if evidence.NodeUID == "" || (e.Plan.Role == bootstrap.RoleServer && (evidence.EtcdClusterID == "" || evidence.EtcdMemberID == "" || evidence.VotingServers < e.Plan.MinVotingServers)) {
		return ErrWaiting
	}
	if c.Evidence.NodeUID != "" && (c.Evidence.NodeUID != evidence.NodeUID || c.Evidence.EtcdClusterID != evidence.EtcdClusterID || c.Evidence.EtcdMemberID != evidence.EtcdMemberID) {
		return ErrReconcile
	}
	if op.Phase != "Healthy" {
		c.Evidence = evidence
		return advance("Healthy")
	}
	return nil
}
