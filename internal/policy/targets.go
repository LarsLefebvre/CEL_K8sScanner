package policy

import (
	"strings"

	"github.com/larslefebvre/kscan/internal/inventory"
)

// podSpecPath says where each kind keeps its pod spec.
var podSpecPath = map[string][]string{
	"Pod":         {"spec"},
	"Deployment":  {"spec", "template", "spec"},
	"StatefulSet": {"spec", "template", "spec"},
	"DaemonSet":   {"spec", "template", "spec"},
	"ReplicaSet":  {"spec", "template", "spec"},
	"Job":         {"spec", "template", "spec"},
	"CronJob":     {"spec", "jobTemplate", "spec", "template", "spec"},
}

// controllerKinds are owners whose children should not be reported twice.
var controllerKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"ReplicaSet": true, "Job": true, "CronJob": true,
}

// target is one object a policy is evaluated against, with derived fields.
type target struct {
	obj         inventory.Object
	podSpec     any // map or nil
	podSpecPath string
	containers  []any
}

func newTarget(obj inventory.Object) target {
	t := target{obj: obj, containers: []any{}}
	kind, _, _ := inventory.Meta(obj)
	path, ok := podSpecPath[kind]
	if !ok {
		return t
	}
	spec, ok := inventory.Nested(obj, path...)
	if !ok {
		return t
	}
	specMap, ok := spec.(map[string]any)
	if !ok {
		return t
	}
	t.podSpec = specMap
	t.podSpecPath = strings.Join(path, ".")
	for _, field := range []string{"initContainers", "containers", "ephemeralContainers"} {
		if cs, ok := specMap[field].([]any); ok {
			t.containers = append(t.containers, cs...)
		}
	}
	return t
}

// isControlled reports whether obj is managed by a controller kind the
// scanner also evaluates (so findings belong on the owner instead).
func isControlled(obj inventory.Object) bool {
	refs, _ := inventory.Nested(obj, "metadata", "ownerReferences")
	list, _ := refs.([]any)
	for _, r := range list {
		ref, _ := r.(map[string]any)
		if c, _ := ref["controller"].(bool); c {
			kind, _ := ref["kind"].(string)
			return controllerKinds[kind]
		}
	}
	return false
}

// workloads returns top-level pod-producing objects.
func workloads(inv *inventory.Inventory) []inventory.Object {
	var out []inventory.Object
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "CronJob", "ReplicaSet", "Job", "Pod"} {
		for _, obj := range inv.Objects[kind] {
			if !isControlled(obj) {
				out = append(out, obj)
			}
		}
	}
	return out
}

// clusterContext builds the cross-resource lookups exposed as `cluster`.
func clusterContext(inv *inventory.Inventory) map[string]any {
	key := func(obj inventory.Object) string {
		_, ns, name := inventory.Meta(obj)
		if ns == "" {
			return name
		}
		return ns + "/" + name
	}
	byKey := func(kind string) map[string]any {
		m := map[string]any{}
		for _, obj := range inv.Objects[kind] {
			m[key(obj)] = obj
		}
		return m
	}

	netpols := []any{}
	for _, obj := range inv.Objects["NetworkPolicy"] {
		netpols = append(netpols, obj)
	}
	counts := map[string]any{}
	for _, obj := range workloads(inv) {
		_, ns, _ := inventory.Meta(obj)
		n, _ := counts[ns].(int64)
		counts[ns] = n + 1
	}

	return map[string]any{
		// live is false when scanning manifest files, where references to
		// objects that only exist in the cluster can't be resolved.
		"live":            strings.HasPrefix(inv.Source, "cluster:"),
		"clusterRoles":    byKey("ClusterRole"),
		"roles":           byKey("Role"), // keyed "namespace/name"
		"serviceAccounts": byKey("ServiceAccount"),
		"networkPolicies": netpols,
		"workloadCounts":  counts, // namespace -> number of top-level workloads
	}
}
