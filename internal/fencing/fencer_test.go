package fencing

import (
	"testing"
	"time"
)

func TestEvidenceConfirmsFenceOnlyForFreshExactTarget(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	target := Target{HostID: "host-1", DomainUUID: "domain-uuid-1"}
	valid := Evidence{
		Target:      target,
		State:       PowerOffConfirmed,
		ObservedAt:  now.Add(-10 * time.Second),
		Backend:     "libvirt",
		OperationID: "op-123",
		EvidenceID:  "evidence-456",
	}

	tests := []struct {
		name  string
		event Evidence
		want  bool
	}{
		{name: "fresh exact confirmed target", event: valid, want: true},
		{name: "power state unknown", event: func() Evidence { e := valid; e.State = PowerUnknown; return e }(), want: false},
		{name: "different host", event: func() Evidence { e := valid; e.Target.HostID = "other-host"; return e }(), want: false},
		{name: "stale evidence", event: func() Evidence { e := valid; e.ObservedAt = now.Add(-2 * time.Minute); return e }(), want: false},
		{name: "missing operation id", event: func() Evidence { e := valid; e.OperationID = ""; return e }(), want: false},
		{name: "missing evidence id", event: func() Evidence { e := valid; e.EvidenceID = ""; return e }(), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.event.ConfirmsOffFor(target, now, time.Minute); got != tt.want {
				t.Fatalf("ConfirmsOffFor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvidenceRejectsFutureTimestampAndNonPositiveFreshness(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	target := Target{HostID: "host-1", DomainUUID: "domain-uuid-1"}
	e := Evidence{
		Target: target, State: PowerOffConfirmed, ObservedAt: now.Add(time.Second),
		Backend: "libvirt", OperationID: "op-1", EvidenceID: "e-1",
	}
	if e.ConfirmsOffFor(target, now, time.Minute) {
		t.Fatal("future-dated evidence must not confirm fencing")
	}
	e.ObservedAt = now
	if e.ConfirmsOffFor(target, now, 0) {
		t.Fatal("non-positive freshness window must not confirm fencing")
	}
}
