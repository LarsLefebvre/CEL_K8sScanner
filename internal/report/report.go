// Package report defines scan findings and renders them as JSON, a terminal
// table, or Prometheus metrics.
package report

import (
	"fmt"

	"github.com/larslefebvre/kscan/internal/inventory"
	"github.com/larslefebvre/kscan/internal/taxonomy"
	"sort"
	"strings"
	"time"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Severities in descending order.
var Severities = []Severity{Critical, High, Medium, Low, Info}

func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	}
	return 0
}

func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToLower(strings.TrimSpace(s)))
	if sev.Rank() == 0 {
		return "", fmt.Errorf("unknown severity %q (want critical|high|medium|low|info)", s)
	}
	return sev, nil
}

type Resource struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

func (r Resource) String() string {
	if r.Namespace == "" {
		return r.Kind + "/" + r.Name
	}
	return r.Kind + " " + r.Namespace + "/" + r.Name
}

type Finding struct {
	PolicyID   string   `json:"policyId"`
	PolicyName string   `json:"policyName"`
	Severity   Severity `json:"severity"`
	Tactic     string   `json:"tactic"`
	// Techniques are ATT&CK Containers matrix techniques; MatrixTechniques
	// are Redguard Kubernetes Threat Matrix techniques.
	Techniques       []taxonomy.Technique       `json:"techniques,omitempty"`
	MatrixTechniques []taxonomy.MatrixTechnique `json:"matrixTechniques,omitempty"`
	Resource         Resource                   `json:"resource"`
	Message          string                     `json:"message"`
	Remediation      string                     `json:"remediation,omitempty"`
	References       []string                   `json:"references,omitempty"`
	Evidence         *Evidence                  `json:"evidence,omitempty"`
}

// PolicyError is a policy that failed to evaluate against an object (e.g. a
// runtime type error in its CEL expression).
type PolicyError struct {
	PolicyID string   `json:"policyId"`
	Resource Resource `json:"resource"`
	Error    string   `json:"error"`
}

type Summary struct {
	Total             int              `json:"total"`
	BySeverity        map[Severity]int `json:"bySeverity"`
	ByTactic          map[string]int   `json:"byTactic"`
	ByTechnique       map[string]int   `json:"byTechnique"`
	ByPolicy          map[string]int   `json:"byPolicy"`
	ResourcesAffected int              `json:"resourcesAffected"`
	// Score is a coarse 0-100 posture score (100 = no findings). Each
	// distinct (policy, resource) pair costs points weighted by severity.
	Score int `json:"score"`
}

type Report struct {
	Cluster           inventory.ClusterInfo `json:"cluster"`
	Source            string                `json:"source"`
	GeneratedAt       time.Time             `json:"generatedAt"`
	DurationMs        int64                 `json:"durationMs"`
	ObjectsScanned    int                   `json:"objectsScanned"`
	PoliciesEvaluated int                   `json:"policiesEvaluated"`
	// Evaluations is the number of (policy, object) pairs evaluated.
	Evaluations      int           `json:"evaluations"`
	Summary          Summary       `json:"summary"`
	Findings         []Finding     `json:"findings"`
	PolicyErrors     []PolicyError `json:"policyErrors,omitempty"`
	CollectionErrors []string      `json:"collectionErrors,omitempty"`
}

// Finalize sorts findings (most severe first) and computes the summary.
func (r *Report) Finalize() {
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.PolicyID != b.PolicyID {
			return a.PolicyID < b.PolicyID
		}
		if a.Resource.Namespace != b.Resource.Namespace {
			return a.Resource.Namespace < b.Resource.Namespace
		}
		if a.Resource.Name != b.Resource.Name {
			return a.Resource.Name < b.Resource.Name
		}
		return a.Message < b.Message
	})

	s := Summary{BySeverity: map[Severity]int{}, ByTactic: map[string]int{}, ByTechnique: map[string]int{}, ByPolicy: map[string]int{}}
	for _, sev := range Severities {
		s.BySeverity[sev] = 0
	}
	resources := map[string]bool{}
	pairs := map[string]Severity{}
	for _, f := range r.Findings {
		s.Total++
		s.BySeverity[f.Severity]++
		s.ByTactic[f.Tactic]++
		for _, t := range f.Techniques {
			s.ByTechnique[t.ID]++
		}
		s.ByPolicy[f.PolicyID]++
		resources[f.Resource.String()] = true
		pairs[f.PolicyID+"|"+f.Resource.String()] = f.Severity
	}
	s.ResourcesAffected = len(resources)

	penalty := 0.0
	for _, sev := range pairs {
		penalty += map[Severity]float64{Critical: 10, High: 5, Medium: 2, Low: 0.5, Info: 0}[sev]
	}
	// Asymptotic so the score never goes negative and still moves on big clusters.
	s.Score = int(100 * 100 / (100 + penalty))
	r.Summary = s
}

// CountAtOrAbove returns how many findings have severity >= min.
func (r *Report) CountAtOrAbove(min Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity.Rank() >= min.Rank() {
			n++
		}
	}
	return n
}

// Evidence shows where a finding was found and how to fix it, as YAML.
type Evidence struct {
	// Target is the object the YAML belongs to. It is usually the finding's
	// resource, but e.g. for a binding it can be the Role that grants too much.
	Target Resource `json:"target"`
	Path   string   `json:"path,omitempty"`
	// Found is the offending fragment, nested at its real location.
	Found string `json:"found,omitempty"`
	// Fix is either a strategic-merge patch for Target or a full manifest.
	Fix string `json:"fix,omitempty"`
	// Action is patch | create | replace | delete.
	Action  string `json:"action,omitempty"`
	Command string `json:"command,omitempty"`
}

// BuildCommand returns the kubectl command that applies the evidence's fix.
func (e *Evidence) BuildCommand() {
	kind := strings.ToLower(e.Target.Kind)
	ns := ""
	if e.Target.Namespace != "" {
		ns = " -n " + e.Target.Namespace
	}
	switch e.Action {
	case "patch":
		e.Command = fmt.Sprintf("kubectl patch %s %s%s --type strategic --patch-file fix.yaml", kind, e.Target.Name, ns)
		if e.Target.Kind == "Pod" {
			e.Command = "# Pod specs are mostly immutable: apply the fix to the manifest, then delete and re-create the pod"
		}
	case "create":
		e.Command = "kubectl apply -f fix.yaml"
	case "replace":
		e.Command = fmt.Sprintf("kubectl delete %s %s%s && kubectl apply -f fix.yaml", kind, e.Target.Name, ns)
	case "delete":
		e.Command = fmt.Sprintf("kubectl delete %s %s%s", kind, e.Target.Name, ns)
	}
}
