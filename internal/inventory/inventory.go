// Package inventory holds the raw Kubernetes objects collected from a cluster
// (or from manifest files) in a source-agnostic shape the policy engine reads.
package inventory

import (
	"fmt"
	"sort"
	"time"
)

// Object is an unstructured Kubernetes object (the decoded JSON form).
type Object = map[string]any

// ClusterInfo describes the scanned cluster for display in reports.
type ClusterInfo struct {
	Name       string     `json:"name"`
	Server     string     `json:"server,omitempty"`
	Version    string     `json:"version,omitempty"`
	Platform   string     `json:"platform,omitempty"`
	Nodes      []NodeInfo `json:"nodes,omitempty"`
	Namespaces int        `json:"namespaces"`
	Workloads  int        `json:"workloads"`
}

type NodeInfo struct {
	Name    string   `json:"name"`
	Roles   []string `json:"roles,omitempty"`
	Version string   `json:"version,omitempty"`
	OS      string   `json:"os,omitempty"`
	Runtime string   `json:"runtime,omitempty"`
	Ready   bool     `json:"ready"`
}

// Inventory is a point-in-time snapshot of the resources a scan looks at.
type Inventory struct {
	Cluster     ClusterInfo         `json:"cluster"`
	Source      string              `json:"source"`
	CollectedAt time.Time           `json:"collectedAt"`
	Objects     map[string][]Object `json:"-"`
	// Errors are non-fatal collection problems (e.g. a resource type the
	// scanner is not allowed to list). The scan continues without that type.
	Errors []string `json:"errors,omitempty"`
}

func New(source string) *Inventory {
	return &Inventory{Source: source, CollectedAt: time.Now().UTC(), Objects: map[string][]Object{}}
}

func (inv *Inventory) Add(obj Object) {
	kind, _ := obj["kind"].(string)
	if kind == "" {
		return
	}
	inv.Objects[kind] = append(inv.Objects[kind], obj)
}

func (inv *Inventory) Errorf(format string, args ...any) {
	inv.Errors = append(inv.Errors, fmt.Sprintf(format, args...))
}

// Count returns the total number of objects in the inventory.
func (inv *Inventory) Count() int {
	n := 0
	for _, objs := range inv.Objects {
		n += len(objs)
	}
	return n
}

// Kinds returns the collected kinds in a stable order.
func (inv *Inventory) Kinds() []string {
	kinds := make([]string, 0, len(inv.Objects))
	for k := range inv.Objects {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

// Meta returns name, namespace, and kind of an object.
func Meta(obj Object) (kind, namespace, name string) {
	kind, _ = obj["kind"].(string)
	if md, ok := obj["metadata"].(map[string]any); ok {
		namespace, _ = md["namespace"].(string)
		name, _ = md["name"].(string)
	}
	return
}

// Annotations returns the object's annotations (never nil).
func Annotations(obj Object) map[string]any {
	if md, ok := obj["metadata"].(map[string]any); ok {
		if a, ok := md["annotations"].(map[string]any); ok {
			return a
		}
	}
	return map[string]any{}
}

// Nested walks a path of map keys and returns the value found, if any.
func Nested(obj map[string]any, path ...string) (any, bool) {
	var cur any = obj
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
