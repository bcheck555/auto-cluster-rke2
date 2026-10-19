package formation

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// checkConnectivity uses two disposable pods on distinct controls and their
// ClusterIP service. Namespace ownership is verified before every cleanup.
func (k KubeBackend) checkConnectivity(ctx context.Context, op HealingOperation, peer Member) error {
	if k.connectivity != nil {
		return k.connectivity(ctx, op)
	}
	data, err := k.file("/etc/autonomous-rke2/image.json", false)
	if err != nil {
		return err
	}
	var image struct {
		ValidationImage string `json:"validation_image"`
	}
	if json.Unmarshal(data, &image) != nil || !strings.HasPrefix(image.ValidationImage, "docker.io/library/busybox@sha256:") {
		return ErrInvalid
	}
	status, err := k.managementStatus(ctx)
	if err != nil {
		return err
	}
	replacement, ok := status.Catalog.Members[op.Candidate.ID]
	if !ok {
		return ErrWaiting
	}
	current, ok := status.Catalog.Members[peer.ID]
	if !ok || peer.ID == replacement.ID || !sameMember(current, peer) || !current.Complete || current.Retiring || current.Role != "server" {
		return ErrWaiting
	}
	other := peer.NodeName
	ns := "autonomous-rke2-heal-" + op.ID[:12]
	labels := map[string]string{"autonomous-rke2.io/cluster-id": k.ClusterID, "autonomous-rke2.io/healing-operation": op.ID}
	ensureOwnership := func() error {
		data, code, err := k.call(ctx, false, http.MethodGet, "/api/v1/namespaces/"+ns, nil)
		if err != nil || code != 200 {
			return ErrWaiting
		}
		var existing struct {
			Metadata struct{ Labels map[string]string }
		}
		if json.Unmarshal(data, &existing) != nil {
			return ErrConflict
		}
		for key, value := range labels {
			if existing.Metadata.Labels[key] != value {
				return ErrConflict
			}
		}
		return nil
	}
	data, code, err := k.call(ctx, false, http.MethodGet, "/api/v1/namespaces/"+ns, nil)
	_ = data
	if err != nil {
		return err
	}
	if code == 404 {
		_, code, err = k.call(ctx, false, http.MethodPost, "/api/v1/namespaces", map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns, "labels": labels}})
		if err != nil || (code != 201 && code != 409) {
			return ErrWaiting
		}
	}
	if err := ensureOwnership(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, nativeKubectl, append([]string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", ns}, args...)...)
		return cmd.Run()
	}
	// A retry starts with the same owned probe resources, never duplicates them.
	for _, resource := range []string{"pods/server", "pods/client", "services/probe"} {
		if err := k.cleanupHealingProbe(ctx, ns, resource, labels); err != nil {
			return err
		}
	}
	server := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "server", "namespace": ns, "labels": map[string]string{"app": "healing-probe"}}, "spec": map[string]any{"nodeName": other, "restartPolicy": "Never", "containers": []any{map[string]any{"name": "http", "image": image.ValidationImage, "imagePullPolicy": "Never", "command": []string{"sh", "-c", "mkdir -p /tmp/heal; echo healthy >/tmp/heal/index.html; exec httpd -f -p 8080 -h /tmp/heal"}}}}}
	service := map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "probe", "namespace": ns}, "spec": map[string]any{"selector": map[string]string{"app": "healing-probe"}, "ports": []any{map[string]any{"port": 8080, "targetPort": 8080}}}}
	client := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "client", "namespace": ns}, "spec": map[string]any{"nodeName": replacement.NodeName, "restartPolicy": "Never", "containers": []any{map[string]any{"name": "client", "image": image.ValidationImage, "imagePullPolicy": "Never", "command": []string{"sh", "-c", "for i in $(seq 1 15); do wget -q -O- -T 2 http://probe." + ns + ".svc.cluster.local:8080/ | grep -q '^healthy$' && exit 0; sleep 1; done; exit 1"}}}}}
	for _, resource := range []map[string]any{server, service, client} {
		metadata := resource["metadata"].(map[string]any)
		owned := map[string]string{}
		for key, value := range labels {
			owned[key] = value
		}
		if resource["kind"] == "Pod" && metadata["name"] == "server" {
			owned["app"] = "healing-probe"
		}
		metadata["labels"] = owned
		if resource["kind"] == "Pod" {
			resource["spec"].(map[string]any)["automountServiceAccountToken"] = false
		}
		kind := "pods"
		if resource["kind"] == "Service" {
			kind = "services"
		}
		_, code, err := k.call(ctx, false, http.MethodPost, "/api/v1/namespaces/"+ns+"/"+kind, resource)
		if err != nil || code != 201 {
			return ErrWaiting
		}
	}
	if err := run("wait", "pod/client", "--for=jsonpath={.status.phase}=Succeeded", "--timeout=40s"); err != nil {
		return ErrWaiting
	}
	if err := ensureOwnership(); err != nil {
		return err
	}
	if err := run("delete", "namespace", ns, "--wait=false"); err != nil {
		return ErrWaiting
	}
	return nil
}

// These exact, operation-owned diagnostic resources contain no application
// volumes. UID-preconditioned deletion allows retries even if their host went
// offline; it never force-drains workloads or removes unrelated pod objects.
func (k KubeBackend) cleanupHealingProbe(ctx context.Context, ns, resource string, labels map[string]string) error {
	path := "/api/v1/namespaces/" + ns + "/" + resource
	data, code, err := k.call(ctx, false, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if code == 404 {
		return nil
	}
	if code != 200 {
		return ErrWaiting
	}
	var value struct {
		Metadata struct {
			UID        string
			Labels     map[string]string
			Finalizers []string
		}
	}
	if json.Unmarshal(data, &value) != nil || value.Metadata.UID == "" {
		return ErrConflict
	}
	for key, expected := range labels {
		if value.Metadata.Labels[key] != expected {
			return ErrConflict
		}
	}
	if len(value.Metadata.Finalizers) != 0 {
		return ErrWaiting
	}
	_, code, err = k.call(ctx, false, http.MethodDelete, path, map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 0, "preconditions": map[string]string{"uid": value.Metadata.UID}})
	if err != nil {
		return err
	}
	if code != 200 && code != 202 && code != 404 {
		return ErrWaiting
	}
	return nil
}
