package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignedStatusResolvesLostConsumptionResponse(t *testing.T) {
	f := setupAt(t, t.TempDir(), 1)
	ctx := context.Background()
	g := f.bootstrap(t)
	s, err := f.a.GrantStatus(ctx, g.HostID, g.OperationID, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if s.Consumed || s.Bootstrap == nil {
		t.Fatal("unexpected issuance state")
	}
	if err := f.a.ConsumeBootstrapGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	s, err = f.a.GrantStatus(ctx, g.HostID, g.OperationID, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.a.Verifier().VerifyGrantStatus(ctx, s, g.HostID, g.OperationID, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if !s.Consumed {
		t.Fatal("consumption lost")
	}
	if err := f.a.Verifier().VerifyGrantStatus(ctx, s, g.HostID, g.OperationID, strings.Repeat("a", 64)); err == nil {
		t.Fatal("replayed status accepted")
	}
	if _, err := f.a.GrantStatus(ctx, g.HostID, "missing", strings.Repeat("c", 64)); !errors.Is(err, ErrGrantNotFound) {
		t.Fatal(err)
	}
}

func TestConsumedStatusAllowsRestartAfterGrantExpiry(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		f := setupAt(t, t.TempDir(), 1)
		ctx := context.Background()
		g := f.bootstrap(t)
		if consumed {
			if err := f.a.ConsumeBootstrapGrant(ctx, g); err != nil {
				t.Fatal(err)
			}
		}
		now := g.ExpiresAt.Add(time.Minute)
		f.a.now = func() time.Time { return now }
		v := f.a.Verifier()
		v.now = func() time.Time { return now }
		s, err := f.a.GrantStatus(ctx, g.HostID, g.OperationID, strings.Repeat("c", 64))
		if err != nil {
			t.Fatal(err)
		}
		err = v.VerifyGrantStatus(ctx, s, g.HostID, g.OperationID, strings.Repeat("c", 64))
		if consumed && err != nil {
			t.Fatal(err)
		}
		if !consumed && !errors.Is(err, ErrExpired) {
			t.Fatalf("expired unconsumed grant: %v", err)
		}
	}
}
