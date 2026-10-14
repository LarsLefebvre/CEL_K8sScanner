// Package policy loads CEL policies and evaluates them against an inventory.
//
// A policy is a small YAML document. Its `violations` expression is CEL and
// returns either:
//   - a bool: true means the object violates the policy (reported with `message`), or
//   - a list of strings: one finding per element, which lets a single policy
//     say exactly which container / rule / subject is the problem.
package policy

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/larslefebvre/kscan/internal/collector"
	"github.com/larslefebvre/kscan/internal/report"
	"github.com/larslefebvre/kscan/internal/taxonomy"
)

// WorkloadKind is a pseudo-kind matching every top-level pod-producing object
// (Deployment, StatefulSet, DaemonSet, CronJob, and Pods/ReplicaSets/Jobs that
// no controller owns). Matching it avoids reporting the same issue on a
// Deployment, its ReplicaSet, and every Pod.
const WorkloadKind = "Workload"

type Policy struct {
	// ID is a descriptive kebab-case key (e.g. "privileged-container") used
	// for overrides and suppressions. Threat classification lives in Tactic,
	// MITRE and ThreatMatrix, which must reference real catalog entries.
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Severity    report.Severity `json:"severity"`
	// Tactic is the ATT&CK tactic this check primarily defends against.
	Tactic string `json:"tactic"`
	// MITRE lists ATT&CK Containers matrix technique IDs, e.g. T1611, T1552.007.
	MITRE []string `json:"mitre,omitempty"`
	// ThreatMatrix lists Redguard Kubernetes Threat Matrix technique paths,
	// e.g. "privilege-escalation/privileged-container".
	ThreatMatrix []string   `json:"threatMatrix,omitempty"`
	Disabled     bool       `json:"disabled,omitempty"`
	Match        Match      `json:"match"`
	Variables    []Variable `json:"variables,omitempty"`
	Violations   string     `json:"violations"`
	Message      string     `json:"message,omitempty"`
	Remediation  string     `json:"remediation,omitempty"`
	References   []string   `json:"references,omitempty"`

	// Resolved from MITRE / ThreatMatrix during validation (output only).
	Techniques       []taxonomy.Technique       `json:"techniques,omitempty"`
	MatrixTechniques []taxonomy.MatrixTechnique `json:"matrixTechniques,omitempty"`

	// Origin is where the policy was loaded from (for error messages).
	Origin string `json:"-"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

type Match struct {
	Kinds             []string `json:"kinds"`
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`
}

// Variable is a named CEL expression evaluated before `violations` and
// exposed as variables.<name>. Later variables may reference earlier ones.
type Variable struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
}

func (p *Policy) validate() error {
	var errs []string
	if !idPattern.MatchString(p.ID) {
		errs = append(errs, fmt.Sprintf("id %q must be kebab-case, e.g. privileged-container", p.ID))
	}
	if p.Name == "" {
		errs = append(errs, "name is required")
	}
	if p.Severity.Rank() == 0 {
		errs = append(errs, fmt.Sprintf("severity %q must be one of critical|high|medium|low|info", p.Severity))
	}
	if len(p.Match.Kinds) == 0 {
		errs = append(errs, "match.kinds must list at least one kind")
	}
	if strings.TrimSpace(p.Violations) == "" {
		errs = append(errs, "violations expression is required")
	}
	for _, v := range p.Variables {
		if v.Name == "" || v.Expression == "" {
			errs = append(errs, "every variable needs a name and an expression")
		}
	}
	if !taxonomy.IsTactic(p.Tactic) {
		names := make([]string, len(taxonomy.Tactics))
		for i, t := range taxonomy.Tactics {
			names[i] = t.Name
		}
		errs = append(errs, fmt.Sprintf("tactic %q must be an ATT&CK Containers tactic: %s", p.Tactic, strings.Join(names, ", ")))
	}
	p.Techniques, p.MatrixTechniques = nil, nil
	tacticCovered := len(p.MITRE) == 0
	for _, id := range p.MITRE {
		t, err := taxonomy.LookupTechnique(id)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		tacticCovered = tacticCovered || t.HasTactic(p.Tactic)
		p.Techniques = append(p.Techniques, t)
	}
	if !tacticCovered {
		errs = append(errs, fmt.Sprintf("none of the mitre techniques %v belong to tactic %q", p.MITRE, p.Tactic))
	}
	for _, path := range p.ThreatMatrix {
		t, err := taxonomy.LookupMatrix(path)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		p.MatrixTechniques = append(p.MatrixTechniques, t)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// Parse reads one or more policies from a multi-document YAML stream.
func Parse(data []byte, origin string) ([]Policy, error) {
	docs, err := collector.SplitYAML(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", origin, err)
	}
	var out []Policy
	for i, doc := range docs {
		js, err := yaml.YAMLToJSON(doc)
		if err != nil {
			return nil, fmt.Errorf("%s (doc %d): %w", origin, i+1, err)
		}
		if string(js) == "null" {
			continue
		}
		var p Policy
		dec := json.NewDecoder(strings.NewReader(string(js)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("%s (doc %d): %w", origin, i+1, err)
		}
		p.Origin = origin
		if err := p.validate(); err != nil {
			return nil, fmt.Errorf("%s (policy %q): %w", origin, p.ID, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// LoadFS loads every *.yaml / *.yml policy file in fsys (non-recursive).
// Entries starting with ".." are skipped so a mounted ConfigMap's internal
// symlink directories are ignored.
func LoadFS(fsys fs.FS, label string) ([]Policy, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out []Policy
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "..") || e.IsDir() {
			continue
		}
		if ext := strings.ToLower(filepath.Ext(name)); ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		ps, err := Parse(data, filepath.Join(label, name))
		if err != nil {
			return nil, err
		}
		out = append(out, ps...)
	}
	return out, nil
}

// LoadDir loads policies from a directory on disk.
func LoadDir(dir string) ([]Policy, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	return LoadFS(os.DirFS(dir), dir)
}

// Merge combines policy sets; a later policy with the same ID replaces an
// earlier one, so custom policies can override or disable built-ins.
func Merge(sets ...[]Policy) []Policy {
	index := map[string]int{}
	var out []Policy
	for _, set := range sets {
		for _, p := range set {
			if i, ok := index[p.ID]; ok {
				out[i] = p
				continue
			}
			index[p.ID] = len(out)
			out = append(out, p)
		}
	}
	return out
}
