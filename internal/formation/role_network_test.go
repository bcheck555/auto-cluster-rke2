package formation

import (
	"context"
	"testing"
)

func TestRoleAdmissionPreservesNameAndSubnetWithFreshUID(t *testing.T) {
	f := newHealingFixture(t)
	old := f.members[3]
	f.mu.Lock()
	delete(f.c.Members, old.ID)
	delete(f.nodes, old.NodeName)
	failed := f.members[2]
	delete(f.c.Members, failed.ID)
	delete(f.nodes, failed.NodeName)
	delete(f.voters, failed.EtcdMemberID)
	f.c.Retired = map[string]Member{old.ID: old}
	f.c.Hosts = map[string]HostAssignment{old.ID: {Generation: 1, Role: "server", Address: old.Address, Previous: old, Operation: "owned"}}
	f.mu.Unlock()
	request := old
	request.Generation = 1
	request.RequestID = incarnationRequest(old.ID, 1)
	request.NodeName = incarnationName(old.ID, 1)
	if request.NodeName != old.NodeName {
		t.Fatal("physical hostname changed")
	}
	for i := 0; i < 2; i++ {
		m, err := f.k.Claim(context.Background(), request)
		if err != nil || m.Generation != 1 || m.Role != "server" {
			t.Fatal("fresh role admission", m, err)
		}
	}
	f.mu.Lock()
	node := f.nodes[old.NodeName]
	creates := f.nodeCreates
	f.mu.Unlock()
	if creates != 1 || node.Metadata.UID == old.NodeUID || node.Spec.PodCIDR != old.PodCIDR || node.Metadata.Labels["autonomous-rke2.io/generation"] != "1" {
		t.Fatal("network reservation drift", node, creates)
	}
	if _, err := f.k.Claim(context.Background(), old); err != ErrConflict {
		t.Fatal("retired incarnation enrolled", err)
	}
}

func TestInvalidPodSubnetIsRejected(t *testing.T) {
	for _, value := range []string{"", "10.99.1.0/24", "10.42.1.4/24", "10.42.0.0/16", "fd00::/64"} {
		if validPodSubnet(value) {
			t.Fatal("invalid subnet", value)
		}
	}
	if !validPodSubnet("10.42.42.0/24") {
		t.Fatal("valid subnet rejected")
	}
}
