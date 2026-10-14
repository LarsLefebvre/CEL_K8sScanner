package policy_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/larslefebvre/kscan/internal/collector"
	"github.com/larslefebvre/kscan/internal/inventory"
	"github.com/larslefebvre/kscan/internal/policy"
	"github.com/larslefebvre/kscan/internal/report"
	"github.com/larslefebvre/kscan/policies"
)

func builtinEngine(t *testing.T) *policy.Engine {
	t.Helper()
	ps, err := policy.LoadFS(policies.Builtin, "builtin")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(ps, policy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func scanFiles(t *testing.T, eng *policy.Engine, paths ...string) *report.Report {
	t.Helper()
	inv, err := collector.FromFiles(paths...)
	if err != nil {
		t.Fatal(err)
	}
	rep := eng.Scan(inv)
	for _, e := range rep.PolicyErrors {
		t.Errorf("policy error: %s on %s: %s", e.PolicyID, e.Resource, e.Error)
	}
	return rep
}

func findingsFor(rep *report.Report, resource string) []string {
	var ids []string
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Resource.String() == resource && !seen[f.PolicyID] {
			seen[f.PolicyID] = true
			ids = append(ids, f.PolicyID)
		}
	}
	sort.Strings(ids)
	return ids
}

// Every built-in policy must fire on the deliberately vulnerable playground,
// on the resource it was written for.
func TestVulnerablePlayground(t *testing.T) {
	rep := scanFiles(t, builtinEngine(t), "../../playground/vulnerable")

	want := map[string][]string{
		"DaemonSet vuln-demo/node-agent":         {"privileged-container", "hostpath-mount"},
		"ClusterRoleBinding/alice-cluster-admin": {"admin-binding"},
		"ClusterRoleBinding/everyone-can-view":   {"anonymous-access"},
		"RoleBinding vuln-demo/ci-bot-debugger":  {"exec-into-containers"},
	}
	for res, ids := range want {
		got := strings.Join(findingsFor(rep, res), ",")
		for _, id := range ids {
			if !strings.Contains(","+got+",", ","+id+",") {
				t.Errorf("%s: expected %s, got [%s]", res, id, got)
			}
		}
	}

	// Roles are only risky once bound: unbound roles produce no findings, and
	// admin-equivalent bindings are reported once (admin-binding), not again by
	// the narrower RBAC policies.
	for _, f := range rep.Findings {
		if f.Resource.Kind == "Role" || f.Resource.Kind == "ClusterRole" {
			t.Errorf("unexpected finding on role %s: %s", f.Resource, f.PolicyID)
		}
	}
	// The playground is tuned to a small, readable set of findings.
	if c, h := rep.Summary.BySeverity[report.Critical], rep.Summary.BySeverity[report.High]; c != 3 || h != 2 || rep.Summary.Total != 5 {
		t.Errorf("expected 3 critical + 2 high findings, got %v", rep.Summary.BySeverity)
	}
	// Every finding shows the offending YAML and a fix.
	for _, f := range rep.Findings {
		if f.Evidence == nil || f.Evidence.Found == "" || f.Evidence.Command == "" ||
			(f.Evidence.Fix == "" && f.Evidence.Action != "delete") {
			t.Errorf("%s on %s: missing found/fix evidence: %+v", f.PolicyID, f.Resource, f.Evidence)
		}
	}

	// Workload findings belong on the controller, not on generated children.
	for _, f := range rep.Findings {
		if f.Resource.Kind == "ReplicaSet" || f.Resource.Kind == "Job" {
			t.Errorf("unexpected finding on controlled object %s", f.Resource)
		}
	}
}

// The hardened reference app should be clean.
func TestSecurePlaygroundIsClean(t *testing.T) {
	rep := scanFiles(t, builtinEngine(t), "../../playground/secure")
	for _, f := range rep.Findings {
		t.Errorf("unexpected finding: %s %s: %s", f.PolicyID, f.Resource, f.Message)
	}
}

func TestIgnoreAnnotationAndExcludes(t *testing.T) {
	inv := inventory.New("files:test")
	err := collector.AddManifests(inv, []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: p1
  namespace: a
  annotations:
    kscan.io/ignore: "privileged-container, T1068"
spec:
  containers:
    - {name: c, image: x, securityContext: {privileged: true, runAsUser: 0}}
---
apiVersion: v1
kind: Pod
metadata: {name: p2, namespace: skipped}
spec:
  containers:
    - {name: c, image: x:1, securityContext: {privileged: true}}
`))
	if err != nil {
		t.Fatal(err)
	}
	ps, _ := policy.LoadFS(policies.Builtin, "builtin")
	eng, err := policy.NewEngine(ps, policy.Options{ExcludeNamespaces: []string{"skipped"}})
	if err != nil {
		t.Fatal(err)
	}
	rep := eng.Scan(inv)
	for _, f := range rep.Findings {
		if f.Resource.Namespace == "skipped" {
			t.Errorf("excluded namespace reported: %s", f.PolicyID)
		}
		// T1068 suppresses run-as-root, which is mapped to it.
		if f.Resource.Name == "p1" && (f.PolicyID == "privileged-container" || f.PolicyID == "run-as-root") {
			t.Errorf("ignored policy reported: %s", f.PolicyID)
		}
	}
	if len(findingsFor(rep, "Pod a/p1")) == 0 {
		t.Error("non-ignored policies should still report on p1")
	}
}

func TestCompileErrorsAreReported(t *testing.T) {
	ps, err := policy.Parse([]byte(`
id: bad
name: bad
tactic: Execution
severity: high
match: {kinds: [Pod]}
violations: object.spec.containers.exists(c, c.image ==)
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.NewEngine(ps, policy.Options{}); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("expected compile error naming the policy, got %v", err)
	}

	_, err = policy.Parse([]byte("id: x\nname: x\nseverity: urgent\ntactic: Execution\nmatch: {kinds: [Pod]}\nviolations: 'true'\n"), "test")
	if err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("expected severity validation error, got %v", err)
	}
}

func TestMergeOverridesByID(t *testing.T) {
	a := []policy.Policy{{ID: "a", Name: "one"}, {ID: "b", Name: "b"}}
	b := []policy.Policy{{ID: "a", Name: "two", Disabled: true}}
	got := policy.Merge(a, b)
	if len(got) != 2 || got[0].Name != "two" || !got[0].Disabled {
		t.Fatalf("unexpected merge result %+v", got)
	}
}

// Policies may only reference real MITRE ATT&CK Containers techniques and
// Redguard Kubernetes Threat Matrix techniques.
func TestTaxonomyIsValidated(t *testing.T) {
	base := "id: x\nname: x\nseverity: high\nmatch: {kinds: [Pod]}\nviolations: 'false'\n"
	cases := map[string]string{
		"tactic: Execution\nmitre: [T9999]\n":                            "not a technique",
		"tactic: Execution\nmitre: [T1611]\n":                            "none of the mitre techniques",
		"tactic: Defense Evasion\n":                                      "must be an ATT&CK Containers tactic",
		"tactic: Execution\nthreatMatrix: [execution/hack-the-planet]\n": "not a technique in the Redguard",
		"tactic: Privilege Escalation\nmitre: [T1611]\nthreatMatrix: [privilege-escalation/privileged-container]\n": "",
	}
	for extra, want := range cases {
		_, err := policy.Parse([]byte(base+extra), "test")
		if want == "" {
			if err != nil {
				t.Errorf("valid mapping rejected: %v", err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: expected error containing %q, got %v", extra, want, err)
		}
	}
}

func TestEveryBuiltinPolicyIsMapped(t *testing.T) {
	for _, p := range builtinEngine(t).Policies() {
		if len(p.Techniques) == 0 {
			t.Errorf("%s has no MITRE ATT&CK technique", p.ID)
		}
		for _, tech := range p.Techniques {
			if !strings.HasPrefix(tech.URL, "https://attack.mitre.org/techniques/T") {
				t.Errorf("%s: bad technique URL %s", p.ID, tech.URL)
			}
		}
	}
}
