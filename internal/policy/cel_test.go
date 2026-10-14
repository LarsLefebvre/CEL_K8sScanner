package policy

import (
	"testing"

	"github.com/google/cel-go/common/types"
)

func TestRulesAllow(t *testing.T) {
	rules := types.DefaultTypeAdapter.NativeToValue([]any{
		map[string]any{"apiGroups": []any{""}, "resources": []any{"pods", "pods/exec"}, "verbs": []any{"get", "create"}},
		map[string]any{"apiGroups": []any{"apps"}, "resources": []any{"*"}, "verbs": []any{"list"}},
		map[string]any{"apiGroups": []any{"*"}, "resources": []any{"*/scale"}, "verbs": []any{"update"}},
		map[string]any{"nonResourceURLs": []any{"/healthz"}, "verbs": []any{"get"}},
	})
	cases := []struct {
		verb, group, resource string
		want                  bool
	}{
		{"create", "", "pods/exec", true},
		{"get", "", "pods", true},
		{"delete", "", "pods", false},
		{"get", "", "secrets", false},
		{"list", "apps", "deployments", true},
		{"list", "batch", "jobs", false},
		{"update", "apps", "deployments/scale", true},
		{"update", "apps", "deployments", false},
		{"create", "apps", "pods/exec", false}, // wrong group
	}
	for _, c := range cases {
		if got := rulesAllow(rules, c.verb, c.group, c.resource); got != c.want {
			t.Errorf("allows(%q, %q, %q) = %v, want %v", c.verb, c.group, c.resource, got, c.want)
		}
	}
}
