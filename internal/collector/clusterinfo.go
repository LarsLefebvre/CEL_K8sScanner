package collector

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/larslefebvre/kscan/internal/inventory"
)

var nodesGVR = gvr("", "v1", "nodes")

// ClusterName picks a display name for the cluster: an explicit name wins,
// then the kubeconfig context in use, then "in-cluster".
func ClusterName(explicit, kubeconfig, context string) string {
	if explicit != "" {
		return explicit
	}
	if context != "" {
		return context
	}
	if _, inCluster := os.LookupEnv("KUBERNETES_SERVICE_HOST"); inCluster && kubeconfig == "" {
		return "in-cluster"
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	if cfg, err := rules.Load(); err == nil && cfg.CurrentContext != "" {
		return cfg.CurrentContext
	}
	return "unknown"
}

// clusterInfo gathers display metadata. Every part is best-effort: missing
// permissions just leave fields empty.
func (c *Cluster) clusterInfo(ctx context.Context) inventory.ClusterInfo {
	info := inventory.ClusterInfo{Name: c.name, Server: c.host}
	if v, err := c.discovery.ServerVersion(); err == nil {
		info.Version = v.GitVersion
	} else {
		slog.Debug("server version unavailable", "err", err)
	}

	list, err := c.client.Resource(nodesGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.Debug("node list unavailable", "err", err)
		info.Platform = platformFromVersion(info.Version)
		return info
	}
	for _, n := range list.Items {
		obj := n.Object
		node := inventory.NodeInfo{Name: n.GetName()}
		for label := range n.GetLabels() {
			if role, ok := strings.CutPrefix(label, "node-role.kubernetes.io/"); ok && role != "" {
				node.Roles = append(node.Roles, role)
			}
		}
		sort.Strings(node.Roles)
		if ni, ok := inventory.Nested(obj, "status", "nodeInfo"); ok {
			m, _ := ni.(map[string]any)
			node.Version, _ = m["kubeletVersion"].(string)
			node.OS, _ = m["osImage"].(string)
			node.Runtime, _ = m["containerRuntimeVersion"].(string)
		}
		if conds, ok := inventory.Nested(obj, "status", "conditions"); ok {
			for _, cnd := range conds.([]any) {
				m, _ := cnd.(map[string]any)
				if m["type"] == "Ready" && m["status"] == "True" {
					node.Ready = true
				}
			}
		}
		if info.Platform == "" {
			if pid, ok := inventory.Nested(obj, "spec", "providerID"); ok {
				info.Platform = platformFromProviderID(pid.(string))
			}
		}
		info.Nodes = append(info.Nodes, node)
	}
	sort.Slice(info.Nodes, func(i, j int) bool { return info.Nodes[i].Name < info.Nodes[j].Name })
	if info.Platform == "" {
		info.Platform = platformFromVersion(info.Version)
	}
	return info
}

func platformFromProviderID(id string) string {
	scheme, _, _ := strings.Cut(id, "://")
	switch scheme {
	case "kind":
		return "kind"
	case "aws":
		return "AWS (EKS)"
	case "gce":
		return "Google Cloud (GKE)"
	case "azure":
		return "Azure (AKS)"
	case "k3s":
		return "k3s"
	case "":
		return ""
	}
	return scheme
}

func platformFromVersion(v string) string {
	switch {
	case strings.Contains(v, "-eks"):
		return "AWS (EKS)"
	case strings.Contains(v, "-gke"):
		return "Google Cloud (GKE)"
	case strings.Contains(v, "+k3s"):
		return "k3s"
	}
	return ""
}
