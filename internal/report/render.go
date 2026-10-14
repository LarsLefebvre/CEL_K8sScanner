package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

var sevColor = map[Severity]string{
	Critical: "\033[1;37;41m",
	High:     "\033[1;31m",
	Medium:   "\033[33m",
	Low:      "\033[36m",
	Info:     "\033[37m",
}

const (
	reset = "\033[0m"
	dim   = "\033[2m"
	bold  = "\033[1m"
)

// WriteTable renders a human-oriented report: summary first, then findings
// grouped by resource so each workload's to-do list reads top to bottom.
func WriteTable(w io.Writer, r *Report, color bool) {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + reset
	}

	fmt.Fprintf(w, "%s\n", c(bold, "kscan report: "+r.Cluster.Name))
	if r.Cluster.Version != "" {
		meta := []string{"Kubernetes " + r.Cluster.Version}
		if r.Cluster.Platform != "" {
			meta = append(meta, r.Cluster.Platform)
		}
		if n := len(r.Cluster.Nodes); n > 0 {
			meta = append(meta, fmt.Sprintf("%d nodes", n))
		}
		fmt.Fprintf(w, "  cluster:   %s\n", strings.Join(meta, ", "))
	}
	fmt.Fprintf(w, "  source:    %s\n", r.Source)
	fmt.Fprintf(w, "  scanned:   %d objects, %d policies in %dms\n", r.ObjectsScanned, r.PoliciesEvaluated, r.DurationMs)
	fmt.Fprintf(w, "  score:     %d/100\n", r.Summary.Score)
	fmt.Fprintf(w, "  findings:  %d across %d resources  (", r.Summary.Total, r.Summary.ResourcesAffected)
	parts := []string{}
	for _, sev := range Severities {
		parts = append(parts, c(sevColor[sev], fmt.Sprintf("%s %d", sev, r.Summary.BySeverity[sev])))
	}
	fmt.Fprintf(w, "%s)\n\n", strings.Join(parts, ", "))

	// Group by resource, ordered by the worst finding on each resource.
	type group struct {
		res      Resource
		worst    int
		findings []Finding
	}
	groups := map[string]*group{}
	var order []*group
	for _, f := range r.Findings {
		key := f.Resource.String()
		g, ok := groups[key]
		if !ok {
			g = &group{res: f.Resource}
			groups[key] = g
			order = append(order, g)
		}
		g.findings = append(g.findings, f)
		if f.Severity.Rank() > g.worst {
			g.worst = f.Severity.Rank()
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].worst != order[j].worst {
			return order[i].worst > order[j].worst
		}
		return order[i].res.String() < order[j].res.String()
	})

	for _, g := range order {
		fmt.Fprintf(w, "%s\n", c(bold, g.res.String()))
		for _, f := range g.findings {
			label := fmt.Sprintf("%-8s", strings.ToUpper(string(f.Severity)))
			fmt.Fprintf(w, "  %s %s %s\n", c(sevColor[f.Severity], label), c(dim, techniqueIDs(f)), f.Message)
			fmt.Fprintf(w, "           %s\n", c(dim, taxonomyLine(f)))
			if f.Remediation != "" {
				fmt.Fprintf(w, "           %s\n", c(dim, "fix: "+firstLine(f.Remediation)))
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.PolicyErrors) > 0 {
		fmt.Fprintf(w, "%s\n", c(sevColor[High], fmt.Sprintf("%d policy evaluation errors:", len(r.PolicyErrors))))
		for _, e := range r.PolicyErrors {
			fmt.Fprintf(w, "  %s on %s: %s\n", e.PolicyID, e.Resource, e.Error)
		}
		fmt.Fprintln(w)
	}
	if len(r.CollectionErrors) > 0 {
		fmt.Fprintf(w, "%s\n", c(sevColor[Medium], "collection warnings:"))
		for _, e := range r.CollectionErrors {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
}

// techniqueIDs is the compact ATT&CK label shown in front of a finding.
func techniqueIDs(f Finding) string {
	if len(f.Techniques) == 0 {
		return "[" + f.PolicyID + "]"
	}
	ids := make([]string, len(f.Techniques))
	for i, t := range f.Techniques {
		ids[i] = t.ID
	}
	return "[" + strings.Join(ids, ",") + "]"
}

// taxonomyLine names the ATT&CK techniques and Threat Matrix techniques.
func taxonomyLine(f Finding) string {
	parts := []string{f.Tactic}
	for _, t := range f.Techniques {
		parts = append(parts, t.ID+" "+t.Name)
	}
	line := "ATT&CK: " + strings.Join(parts, " · ")
	if len(f.MatrixTechniques) > 0 {
		var tm []string
		for _, t := range f.MatrixTechniques {
			tm = append(tm, t.Tactic+" › "+t.Name)
		}
		line += " | Threat Matrix: " + strings.Join(tm, ", ")
	}
	return line
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

// WriteMetrics renders the report in the Prometheus text exposition format.
func WriteMetrics(w io.Writer, r *Report) {
	if r == nil {
		fmt.Fprintln(w, "# no scan completed yet")
		return
	}
	fmt.Fprintln(w, "# HELP kscan_findings Number of findings by severity in the latest scan.")
	fmt.Fprintln(w, "# TYPE kscan_findings gauge")
	for _, sev := range Severities {
		fmt.Fprintf(w, "kscan_findings{severity=%q} %d\n", sev, r.Summary.BySeverity[sev])
	}

	sevOf := map[string]Severity{}
	tacticOf := map[string]string{}
	for _, f := range r.Findings {
		sevOf[f.PolicyID] = f.Severity
		tacticOf[f.PolicyID] = f.Tactic
	}
	ids := make([]string, 0, len(r.Summary.ByPolicy))
	for id := range r.Summary.ByPolicy {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Fprintln(w, "# HELP kscan_policy_findings Number of findings per policy in the latest scan.")
	fmt.Fprintln(w, "# TYPE kscan_policy_findings gauge")
	for _, id := range ids {
		fmt.Fprintf(w, "kscan_policy_findings{policy=%q,severity=%q,tactic=%q} %d\n", id, sevOf[id], tacticOf[id], r.Summary.ByPolicy[id])
	}

	techs := make([]string, 0, len(r.Summary.ByTechnique))
	for id := range r.Summary.ByTechnique {
		techs = append(techs, id)
	}
	sort.Strings(techs)
	fmt.Fprintln(w, "# HELP kscan_technique_findings Number of findings per MITRE ATT&CK technique in the latest scan.")
	fmt.Fprintln(w, "# TYPE kscan_technique_findings gauge")
	for _, id := range techs {
		fmt.Fprintf(w, "kscan_technique_findings{technique=%q} %d\n", id, r.Summary.ByTechnique[id])
	}

	fmt.Fprintln(w, "# HELP kscan_score Posture score of the latest scan (0-100, higher is better).")
	fmt.Fprintln(w, "# TYPE kscan_score gauge")
	fmt.Fprintf(w, "kscan_score %d\n", r.Summary.Score)
	fmt.Fprintln(w, "# HELP kscan_objects_scanned Objects evaluated in the latest scan.")
	fmt.Fprintln(w, "# TYPE kscan_objects_scanned gauge")
	fmt.Fprintf(w, "kscan_objects_scanned %d\n", r.ObjectsScanned)
	fmt.Fprintln(w, "# HELP kscan_policy_errors Policy evaluation errors in the latest scan.")
	fmt.Fprintln(w, "# TYPE kscan_policy_errors gauge")
	fmt.Fprintf(w, "kscan_policy_errors %d\n", len(r.PolicyErrors))
	fmt.Fprintln(w, "# HELP kscan_last_scan_timestamp_seconds Unix time of the latest scan.")
	fmt.Fprintln(w, "# TYPE kscan_last_scan_timestamp_seconds gauge")
	fmt.Fprintf(w, "kscan_last_scan_timestamp_seconds %d\n", r.GeneratedAt.Unix())
	fmt.Fprintln(w, "# HELP kscan_scan_duration_seconds Duration of the latest scan.")
	fmt.Fprintln(w, "# TYPE kscan_scan_duration_seconds gauge")
	fmt.Fprintf(w, "kscan_scan_duration_seconds %.3f\n", float64(r.DurationMs)/1000)
}
