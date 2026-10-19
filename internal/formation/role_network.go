package formation

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

func validPodSubnet(value string) bool {
	ip, subnet, err := net.ParseCIDR(value)
	if err != nil || ip.To4() == nil || !subnet.IP.Equal(ip) {
		return false
	}
	ones, bits := subnet.Mask.Size()
	_, pool, _ := net.ParseCIDR("10.42.0.0/16")
	return bits == 32 && ones == 24 && pool.Contains(ip)
}

// Admission reserves the host's existing pod subnet before returning native
// join credentials. This preserves CNI state and local hostname affinity while
// the Node receives a fresh UID. Competing membership is catalog-serialized.
func (k KubeBackend) preserveNodeNetwork(ctx context.Context, m Member) error {
	c, _, status, err := k.load(ctx)
	if err != nil {
		return err
	}
	if status != 200 {
		return ErrWaiting
	}
	a, ok := c.Hosts[m.ID]
	if !ok || a.Generation != m.Generation || a.Previous.Generation+1 != m.Generation || a.Address != m.Address || !validPodSubnet(a.Previous.PodCIDR) {
		return ErrConflict
	}
	cidr := a.Previous.PodCIDR
	if len(a.Previous.PodCIDRs) > 1 || len(a.Previous.PodCIDRs) == 1 && a.Previous.PodCIDRs[0] != cidr {
		return ErrConflict
	}
	path := "/api/v1/nodes/" + m.NodeName
	data, status, err := k.call(ctx, false, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if status == 404 {
		// Do not reserve a subnet already assigned to an unrelated current Node.
		listData, code, listErr := k.call(ctx, false, http.MethodGet, "/api/v1/nodes", nil)
		if listErr != nil || code != 200 {
			return ErrWaiting
		}
		var list struct {
			Items []struct{ Spec struct{ PodCIDR string } }
		}
		if json.Unmarshal(listData, &list) != nil {
			return ErrConflict
		}
		for _, node := range list.Items {
			if node.Spec.PodCIDR == cidr {
				return ErrConflict
			}
		}
		node := map[string]any{"apiVersion": "v1", "kind": "Node", "metadata": map[string]any{"name": m.NodeName, "labels": map[string]string{"autonomous-rke2.io/host-id": m.ID[:32], "autonomous-rke2.io/cluster-id": k.ClusterID, "autonomous-rke2.io/generation": fmt.Sprint(m.Generation), "kubernetes.io/hostname": m.NodeName}}, "spec": map[string]any{"podCIDR": cidr, "podCIDRs": []string{cidr}}}
		_, code, err = k.call(ctx, false, http.MethodPost, "/api/v1/nodes", node)
		if err != nil || (code != 201 && code != 409) {
			return ErrWaiting
		}
		data, status, err = k.call(ctx, false, http.MethodGet, path, nil)
	}
	if err != nil || status != 200 {
		return ErrWaiting
	}
	var node struct {
		Metadata struct {
			UID    string
			Labels map[string]string
		}
		Spec struct {
			PodCIDR  string
			PodCIDRs []string
		}
	}
	if json.Unmarshal(data, &node) != nil || node.Metadata.UID == "" || node.Metadata.UID == a.Previous.NodeUID || node.Spec.PodCIDR != cidr || len(node.Spec.PodCIDRs) != 1 || node.Spec.PodCIDRs[0] != cidr || node.Metadata.Labels["autonomous-rke2.io/host-id"] != m.ID[:32] || node.Metadata.Labels["autonomous-rke2.io/cluster-id"] != k.ClusterID || node.Metadata.Labels["autonomous-rke2.io/generation"] != fmt.Sprint(m.Generation) {
		return ErrConflict
	}
	return nil
}
