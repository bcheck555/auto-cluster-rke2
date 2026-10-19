package formation

import (
	"context"
	"testing"
)

func TestHealingProtectsLocalAndRetainedData(t *testing.T) {
	for _, name := range []string{"empty", "hostpath", "daemon-emptydir", "foreign-system-daemon", "native-flannel", "retained-local-pv", "other-node-pv", "missing-bound-pv", "network-pv"} {
		t.Run(name, func(t *testing.T) {
			f := newHealingFixture(t)
			m := f.members[3]
			pod := map[string]any{"metadata": map[string]any{"namespace": "apps"}, "spec": map[string]any{"volumes": []any{}}}
			wantBlock := true
			switch name {
			case "empty":
				wantBlock = false
			case "hostpath":
				pod["spec"] = map[string]any{"volumes": []any{map[string]any{"hostPath": map[string]string{"path": "/application"}}}}
				f.pods = []map[string]any{pod}
			case "daemon-emptydir":
				pod["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]string{"kind": "DaemonSet", "name": "application"}}
				pod["spec"] = map[string]any{"volumes": []any{map[string]any{"emptyDir": map[string]any{}}}}
				f.pods = []map[string]any{pod}
			case "foreign-system-daemon", "native-flannel":
				owner := "application"
				if name == "native-flannel" {
					owner = "kube-flannel-ds"
					wantBlock = false
				}
				pod["metadata"] = map[string]any{"namespace": "kube-system", "ownerReferences": []any{map[string]string{"kind": "DaemonSet", "name": owner}}}
				pod["spec"] = map[string]any{"volumes": []any{map[string]any{"hostPath": map[string]string{"path": "/etc/cni/net.d"}}}}
				f.pods = []map[string]any{pod}
			case "retained-local-pv", "other-node-pv":
				host := m.NodeName
				if name == "other-node-pv" {
					host = "other-node"
					wantBlock = false
				}
				n := f.nodes[m.NodeName]
				n.Metadata.Labels = map[string]string{"kubernetes.io/hostname": m.NodeName}
				f.nodes[m.NodeName] = n
				f.pvs = []map[string]any{{"metadata": map[string]string{"name": "retained"}, "spec": map[string]any{"local": map[string]string{"path": "/data"}, "nodeAffinity": map[string]any{"required": map[string]any{"nodeSelectorTerms": []any{map[string]any{"matchExpressions": []any{map[string]any{"key": "kubernetes.io/hostname", "operator": "In", "values": []string{host}}}}}}}}}}
			case "missing-bound-pv", "network-pv":
				pod["spec"] = map[string]any{"volumes": []any{map[string]any{"persistentVolumeClaim": map[string]string{"claimName": "data"}}}}
				f.pods = []map[string]any{pod}
				f.pvcs = map[string]map[string]any{"/api/v1/namespaces/apps/persistentvolumeclaims/data": {"spec": map[string]string{"volumeName": "network"}}}
				if name == "network-pv" {
					f.pvs = []map[string]any{{"metadata": map[string]string{"name": "network"}, "spec": map[string]any{"csi": map[string]string{"driver": "example"}}}}
					wantBlock = false
				}
			}
			if err := f.k.protectCandidate(context.Background(), m); (err != nil) != wantBlock {
				t.Fatal("protection mismatch", err, wantBlock)
			}
		})
	}
}

func TestBlockedDrainUncordonsAndSuccessfulDrainStaysCordoned(t *testing.T) {
	for _, blocked := range []bool{true, false} {
		f := newHealingFixture(t)
		m := f.members[3]
		f.k.drain = func(context.Context, Member) error {
			if blocked {
				return ErrWaiting
			}
			return nil
		}
		err := f.k.drainCandidate(context.Background(), m)
		if (err != nil) != blocked {
			t.Fatal(err)
		}
		f.mu.Lock()
		cordoned := f.nodes[m.NodeName].Spec.Unschedulable
		f.mu.Unlock()
		if cordoned == blocked {
			t.Fatal("incorrect scheduling state after drain", blocked, cordoned)
		}
	}
}
