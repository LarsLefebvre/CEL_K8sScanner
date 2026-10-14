// Package collector builds an inventory.Inventory either from a live cluster
// (via the Kubernetes API) or from manifest files on disk.
package collector

import (
	"context"
	"fmt"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/larslefebvre/kscan/internal/inventory"
)

// Resource is one API resource type the scanner collects.
type Resource struct {
	Kind string
	GVR  schema.GroupVersionResource
}

func gvr(group, version, resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
}

// Resources is everything the scanner reads. It deliberately excludes Secrets
// and ConfigMaps: the scanner never needs their contents, so its ClusterRole
// does not grant access to them.
var Resources = []Resource{
	{"Namespace", gvr("", "v1", "namespaces")},
	{"Pod", gvr("", "v1", "pods")},
	{"Service", gvr("", "v1", "services")},
	{"ServiceAccount", gvr("", "v1", "serviceaccounts")},
	{"Deployment", gvr("apps", "v1", "deployments")},
	{"StatefulSet", gvr("apps", "v1", "statefulsets")},
	{"DaemonSet", gvr("apps", "v1", "daemonsets")},
	{"ReplicaSet", gvr("apps", "v1", "replicasets")},
	{"Job", gvr("batch", "v1", "jobs")},
	{"CronJob", gvr("batch", "v1", "cronjobs")},
	{"NetworkPolicy", gvr("networking.k8s.io", "v1", "networkpolicies")},
	{"Ingress", gvr("networking.k8s.io", "v1", "ingresses")},
	{"Role", gvr("rbac.authorization.k8s.io", "v1", "roles")},
	{"ClusterRole", gvr("rbac.authorization.k8s.io", "v1", "clusterroles")},
	{"RoleBinding", gvr("rbac.authorization.k8s.io", "v1", "rolebindings")},
	{"ClusterRoleBinding", gvr("rbac.authorization.k8s.io", "v1", "clusterrolebindings")},
}

// Cluster collects resources from the Kubernetes API.
type Cluster struct {
	client    dynamic.Interface
	discovery discovery.DiscoveryInterface
	host      string
	name      string
}

// RESTConfig prefers in-cluster credentials (when running as a Deployment) and
// falls back to the standard kubeconfig loading rules (KUBECONFIG, ~/.kube/config).
func RESTConfig(kubeconfig, context string) (*rest.Config, error) {
	if kubeconfig == "" && context == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: context}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
}

// NewCluster creates a collector; name is shown in reports (see ClusterName).
func NewCluster(cfg *rest.Config, name string) (*Cluster, error) {
	cfg.UserAgent = "kscan"
	cfg.QPS, cfg.Burst = 20, 40
	c, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	d, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Cluster{client: c, discovery: d, host: cfg.Host, name: name}, nil
}

// Collect lists every resource type. Failures for individual types (RBAC
// forbidden, API not served) are recorded on the inventory and do not abort.
func (c *Cluster) Collect(ctx context.Context) (*inventory.Inventory, error) {
	inv := inventory.New("cluster:" + c.host)
	inv.Cluster = c.clusterInfo(ctx)
	for _, r := range Resources {
		n, err := c.list(ctx, r, inv)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			slog.Warn("list failed", "resource", r.GVR.String(), "err", err)
			inv.Errorf("list %s: %v", r.GVR.Resource, err)
			continue
		}
		slog.Debug("collected", "kind", r.Kind, "count", n)
	}
	if inv.Count() == 0 && len(inv.Errors) > 0 {
		return nil, fmt.Errorf("could not collect any resources: %s", inv.Errors[0])
	}
	return inv, nil
}

func (c *Cluster) list(ctx context.Context, r Resource, inv *inventory.Inventory) (int, error) {
	opts := metav1.ListOptions{Limit: 500}
	n := 0
	for {
		list, err := c.client.Resource(r.GVR).List(ctx, opts)
		if err != nil {
			return n, err
		}
		for i := range list.Items {
			obj := list.Items[i].Object
			// List items don't carry apiVersion/kind; restore them so
			// policies can rely on object.kind.
			obj["kind"] = r.Kind
			obj["apiVersion"] = r.GVR.GroupVersion().String()
			slim(obj)
			inv.Add(obj)
			n++
		}
		if list.GetContinue() == "" {
			return n, nil
		}
		opts.Continue = list.GetContinue()
	}
}

// slim drops bulky metadata that no policy needs.
func slim(obj map[string]any) {
	unstructured.RemoveNestedField(obj, "metadata", "managedFields")
	unstructured.RemoveNestedField(obj, "metadata", "annotations", "kubectl.kubernetes.io/last-applied-configuration")
}
