package formation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const nativeKubectl = "/var/lib/rancher/rke2/bin/kubectl"

func (k KubeBackend) nodeCordon(ctx context.Context, m Member, cordon bool) error {
	patch := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": m.NodeUID}, {"op": "add", "path": "/spec/unschedulable", "value": cordon}}
	_, status, err := k.call(ctx, false, http.MethodPatch, "/api/v1/nodes/"+url.PathEscape(m.NodeName), patch)
	if err != nil {
		return err
	}
	if status != 200 {
		return ErrConflict
	}
	return nil
}

type selectorExpression struct {
	Key      string
	Operator string
	Values   []string
}
type selectorTerm struct {
	MatchExpressions []selectorExpression
	MatchFields      []selectorExpression
}

func matchesSelector(expression selectorExpression, values map[string]string) bool {
	v, exists := values[expression.Key]
	found := false
	for _, choice := range expression.Values {
		if v == choice {
			found = true
		}
	}
	switch expression.Operator {
	case "In":
		return exists && found
	case "NotIn":
		return !exists || !found
	case "Exists":
		return exists
	case "DoesNotExist":
		return !exists
	case "Gt", "Lt":
		if !exists || len(expression.Values) != 1 {
			return false
		}
		a, e := strconv.Atoi(v)
		b, f := strconv.Atoi(expression.Values[0])
		if e != nil || f != nil {
			return false
		}
		if expression.Operator == "Gt" {
			return a > b
		}
		return a < b
	default:
		return false
	}
}
func selectorMatches(terms []selectorTerm, node ManagementNode) bool {
	for _, term := range terms {
		if len(term.MatchExpressions)+len(term.MatchFields) == 0 {
			continue
		}
		matches := true
		for _, expression := range term.MatchExpressions {
			matches = matches && matchesSelector(expression, node.Metadata.Labels)
		}
		for _, expression := range term.MatchFields {
			matches = matches && matchesSelector(expression, map[string]string{"metadata.name": node.Metadata.Name})
		}
		if matches {
			return true
		}
	}
	return false
}

func (k KubeBackend) protectCandidate(ctx context.Context, m Member) error {
	data, status, err := k.call(ctx, false, http.MethodGet, "/api/v1/nodes/"+url.PathEscape(m.NodeName), nil)
	if err != nil || status != 200 {
		return ErrWaiting
	}
	var node ManagementNode
	if json.Unmarshal(data, &node) != nil || node.Metadata.UID != m.NodeUID {
		return ErrConflict
	}
	data, status, err = k.call(ctx, false, http.MethodGet, "/api/v1/pods?fieldSelector="+url.QueryEscape("spec.nodeName="+m.NodeName), nil)
	if err != nil || status != 200 {
		return ErrWaiting
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				Namespace       string
				Annotations     map[string]string
				OwnerReferences []struct {
					Kind string
					Name string
				}
			}
			Spec struct {
				Volumes []struct {
					HostPath              json.RawMessage
					EmptyDir              json.RawMessage
					PersistentVolumeClaim *struct{ ClaimName string }
				}
			}
		}
	}
	if json.Unmarshal(data, &pods) != nil {
		return ErrConflict
	}
	claims := map[string]bool{}
	for _, pod := range pods.Items {
		native := pod.Metadata.Namespace == "kube-system" && pod.Metadata.Annotations["kubernetes.io/config.mirror"] != ""
		for _, owner := range pod.Metadata.OwnerReferences {
			if pod.Metadata.Namespace == "kube-system" && owner.Kind == "DaemonSet" && (owner.Name == "kube-flannel-ds" || strings.HasPrefix(owner.Name, "rke2-traefik")) {
				native = true
			}
		}
		if native {
			continue
		}
		for _, volume := range pod.Spec.Volumes {
			if len(volume.HostPath) > 0 || len(volume.EmptyDir) > 0 {
				return fmt.Errorf("protected node-local pod data: %w", ErrWaiting)
			}
			if volume.PersistentVolumeClaim != nil {
				data, status, err := k.call(ctx, false, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(pod.Metadata.Namespace)+"/persistentvolumeclaims/"+url.PathEscape(volume.PersistentVolumeClaim.ClaimName), nil)
				if err != nil || status != 200 {
					return ErrWaiting
				}
				var pvc struct{ Spec struct{ VolumeName string } }
				if json.Unmarshal(data, &pvc) != nil || pvc.Spec.VolumeName == "" {
					return ErrWaiting
				}
				claims[pvc.Spec.VolumeName] = true
			}
		}
	}
	data, status, err = k.call(ctx, false, http.MethodGet, "/api/v1/persistentvolumes", nil)
	if err != nil || status != 200 {
		return ErrWaiting
	}
	var pvs struct {
		Items []struct {
			Metadata struct{ Name string }
			Spec     struct {
				Local        json.RawMessage
				HostPath     json.RawMessage
				NodeAffinity struct {
					Required struct{ NodeSelectorTerms []selectorTerm }
				}
			}
		}
	}
	if json.Unmarshal(data, &pvs) != nil {
		return ErrConflict
	}
	for _, pv := range pvs.Items {
		delete(claims, pv.Metadata.Name)
		terms := pv.Spec.NodeAffinity.Required.NodeSelectorTerms
		bound := len(pv.Spec.Local) > 0 || len(pv.Spec.HostPath) > 0
		for _, term := range terms {
			for _, e := range term.MatchExpressions {
				bound = bound || e.Key == "kubernetes.io/hostname"
			}
			for _, e := range term.MatchFields {
				bound = bound || e.Key == "metadata.name"
			}
		}
		if bound && (len(terms) == 0 || selectorMatches(terms, node)) {
			return fmt.Errorf("protected node-local PV: %w", ErrWaiting)
		}
	}
	if len(claims) > 0 {
		return fmt.Errorf("bound PV missing: %w", ErrWaiting)
	}
	return nil
}

func (k KubeBackend) drainCandidate(ctx context.Context, m Member) error {
	if err := k.nodeCordon(ctx, m, true); err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = k.nodeCordon(cleanup, m, false)
		}
	}()
	if err := k.protectCandidate(ctx, m); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	if k.drain != nil {
		if err := k.drain(ctx, m); err != nil {
			return err
		}
	} else {
		cmd := exec.CommandContext(ctx, nativeKubectl, "--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "drain", m.NodeName, "--ignore-daemonsets", "--timeout=30s")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("protected drain blocked: %w", ErrWaiting)
		}
	}
	success = true
	return nil
}
