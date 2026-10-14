package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	"github.com/larslefebvre/kscan/internal/inventory"
	"github.com/larslefebvre/kscan/internal/report"
)

// IgnoreAnnotation suppresses policies on a single object. Value is a
// comma-separated list of policy IDs and/or ATT&CK technique IDs (T1611
// suppresses every policy mapped to it; T1552 also covers T1552.007), or "*".
const IgnoreAnnotation = "kscan.io/ignore"

type Options struct {
	// ExcludeNamespaces are skipped by every policy (namespaced objects and
	// the Namespace objects themselves).
	ExcludeNamespaces []string
}

type compiled struct {
	Policy
	vars       []compiledVar
	violations cel.Program
}

type compiledVar struct {
	name string
	prog cel.Program
}

type Engine struct {
	policies []*compiled
	exclude  map[string]bool
}

// CompileError collects every policy that failed to compile.
type CompileError struct{ Errs []error }

func (e *CompileError) Error() string {
	msgs := make([]string, len(e.Errs))
	for i, err := range e.Errs {
		msgs[i] = err.Error()
	}
	return strings.Join(msgs, "\n")
}

// NewEngine type-checks and compiles all enabled policies.
func NewEngine(policies []Policy, opts Options) (*Engine, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, err
	}
	e := &Engine{exclude: map[string]bool{}}
	for _, ns := range opts.ExcludeNamespaces {
		if ns = strings.TrimSpace(ns); ns != "" {
			e.exclude[ns] = true
		}
	}
	var errs []error
	for _, p := range policies {
		if p.Disabled {
			continue
		}
		c, err := compilePolicy(env, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %s (%s): %w", p.ID, p.Origin, err))
			continue
		}
		e.policies = append(e.policies, c)
	}
	if len(errs) > 0 {
		return nil, &CompileError{Errs: errs}
	}
	return e, nil
}

func compileExpr(env *cel.Env, expr string) (*cel.Ast, cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, nil, iss.Err()
	}
	prog, err := env.Program(ast, cel.CostLimit(costLimit), cel.EvalOptions(cel.OptOptimize))
	return ast, prog, err
}

func compilePolicy(env *cel.Env, p Policy) (*compiled, error) {
	c := &compiled{Policy: p}
	for _, v := range p.Variables {
		_, prog, err := compileExpr(env, v.Expression)
		if err != nil {
			return nil, fmt.Errorf("variable %q: %w", v.Name, err)
		}
		c.vars = append(c.vars, compiledVar{name: v.Name, prog: prog})
	}
	ast, prog, err := compileExpr(env, p.Violations)
	if err != nil {
		return nil, fmt.Errorf("violations: %w", err)
	}
	switch ast.OutputType().Kind() {
	case types.BoolKind, types.ListKind, types.DynKind, types.AnyKind:
	default:
		return nil, fmt.Errorf("violations must return bool or list(string), got %s", ast.OutputType())
	}
	c.violations = prog
	return c, nil
}

// Policies returns the enabled, compiled policies.
func (e *Engine) Policies() []Policy {
	out := make([]Policy, len(e.policies))
	for i, c := range e.policies {
		out[i] = c.Policy
	}
	return out
}

// Scan evaluates every policy against the inventory.
func (e *Engine) Scan(inv *inventory.Inventory) *report.Report {
	start := time.Now()
	cluster := inv.Cluster
	cluster.Namespaces = len(inv.Objects["Namespace"])
	cluster.Workloads = len(workloads(inv))
	rep := &report.Report{
		Cluster:           cluster,
		Source:            inv.Source,
		GeneratedAt:       time.Now().UTC(),
		ObjectsScanned:    inv.Count(),
		PoliciesEvaluated: len(e.policies),
		CollectionErrors:  inv.Errors,
	}

	clusterVal := types.DefaultTypeAdapter.NativeToValue(clusterContext(inv))
	targetsByKind := map[string][]target{}
	targetsFor := func(kind string) []target {
		if ts, ok := targetsByKind[kind]; ok {
			return ts
		}
		var objs []inventory.Object
		if kind == WorkloadKind {
			objs = workloads(inv)
		} else {
			objs = inv.Objects[kind]
		}
		ts := make([]target, 0, len(objs))
		for _, o := range objs {
			ts = append(ts, newTarget(o))
		}
		targetsByKind[kind] = ts
		return ts
	}

	seen := map[string]bool{}
	for _, p := range e.policies {
		policyExclude := map[string]bool{}
		for _, ns := range p.Match.ExcludeNamespaces {
			policyExclude[ns] = true
		}
		for _, kind := range p.Match.Kinds {
			for _, t := range targetsFor(kind) {
				k, ns, name := inventory.Meta(t.obj)
				scopeNS := ns
				if k == "Namespace" {
					scopeNS = name
				}
				if e.exclude[scopeNS] || policyExclude[scopeNS] || ignored(t.obj, &p.Policy) {
					continue
				}
				res := report.Resource{Kind: k, Namespace: ns, Name: name}
				res.APIVersion, _ = t.obj["apiVersion"].(string)

				rep.Evaluations++
				viols, err := p.eval(t, clusterVal)
				if err != nil {
					rep.PolicyErrors = append(rep.PolicyErrors, report.PolicyError{PolicyID: p.ID, Resource: res, Error: err.Error()})
					continue
				}
				for _, v := range viols {
					msg := v.message
					key := p.ID + "|" + res.String() + "|" + msg
					if seen[key] {
						continue
					}
					seen[key] = true
					rep.Findings = append(rep.Findings, report.Finding{
						PolicyID:         p.ID,
						PolicyName:       p.Name,
						Severity:         p.Severity,
						Tactic:           p.Tactic,
						Techniques:       p.Techniques,
						MatrixTechniques: p.MatrixTechniques,
						Resource:         res,
						Message:          msg,
						Remediation:      strings.TrimSpace(p.Remediation),
						References:       p.References,
						Evidence:         v.evidence,
					})
				}
			}
		}
	}
	rep.DurationMs = time.Since(start).Milliseconds()
	rep.Finalize()
	return rep
}

func ignored(obj inventory.Object, p *Policy) bool {
	v, _ := inventory.Annotations(obj)[IgnoreAnnotation].(string)
	if v == "" {
		return false
	}
	for _, id := range strings.Split(v, ",") {
		id = strings.TrimSpace(id)
		if id == "*" || strings.EqualFold(id, p.ID) {
			return true
		}
		for _, t := range p.MITRE {
			if strings.EqualFold(id, t) || strings.HasPrefix(strings.ToUpper(t), strings.ToUpper(id)+".") {
				return true
			}
		}
	}
	return false
}

// violation is one element returned by a policy's violations expression.
type violation struct {
	message  string
	evidence *report.Evidence
}

// eval runs the policy against one target. The violations expression may
// return a bool, a list of strings, or a list of maps:
//
//	{'message': string,          // required
//	 'path':    'spec.template.spec', // where found/fix live in the object
//	 'found':   <fragment>,      // the offending YAML, relative to path
//	 'fix':     <fragment>,      // corrected YAML relative to path, or a full manifest
//	 'action':  'patch',         // optional: patch | create | replace | delete
//	 'target':  {'kind':…, 'name':…, 'namespace':…}} // optional: object the fix applies to
func (c *compiled) eval(t target, cluster ref.Val) ([]violation, error) {
	vars := map[string]any{}
	act := map[string]any{
		"object":      t.obj,
		"podSpec":     t.podSpec,
		"podSpecPath": t.podSpecPath,
		"containers":  t.containers,
		"variables":   vars,
		"cluster":     cluster,
	}
	if t.podSpec == nil {
		act["podSpec"] = types.NullValue
	}
	for _, v := range c.vars {
		val, _, err := v.prog.Eval(act)
		if err != nil {
			return nil, fmt.Errorf("variable %q: %w", v.name, err)
		}
		vars[v.name] = val
	}
	out, _, err := c.violations.Eval(act)
	if err != nil {
		return nil, err
	}
	switch v := out.(type) {
	case types.Bool:
		if !v {
			return nil, nil
		}
		msg := c.Message
		if msg == "" {
			msg = c.Name
		}
		return []violation{{message: msg}}, nil
	case types.Null:
		return nil, nil
	case traits.Lister:
		var vs []violation
		it := v.Iterator()
		for it.HasNext() == types.True {
			el := it.Next()
			switch e := el.(type) {
			case types.String:
				vs = append(vs, violation{message: string(e)})
			case traits.Mapper:
				viol, err := c.structured(e, t)
				if err != nil {
					return nil, err
				}
				vs = append(vs, viol)
			default:
				vs = append(vs, violation{message: fmt.Sprint(el.Value())})
			}
		}
		return vs, nil
	}
	return nil, errors.New("violations returned " + string(out.Type().TypeName()) + ", want bool or a list")
}

func (c *compiled) structured(m traits.Mapper, t target) (violation, error) {
	field := func(k string) (any, bool) {
		v, found := m.Find(types.String(k))
		if !found {
			return nil, false
		}
		return toNative(v), true
	}
	msg, _ := field("message")
	ms, ok := msg.(string)
	if !ok || ms == "" {
		return violation{}, errors.New("violation map needs a non-empty 'message' string")
	}
	found, hasFound := field("found")
	fix, hasFix := field("fix")
	if !hasFound && !hasFix {
		return violation{message: ms}, nil
	}

	kind, ns, name := inventory.Meta(t.obj)
	ev := &report.Evidence{Target: report.Resource{Kind: kind, Namespace: ns, Name: name}}
	if tgt, ok := field("target"); ok {
		if tm, ok := tgt.(map[string]any); ok {
			ev.Target.Kind, _ = tm["kind"].(string)
			ev.Target.Name, _ = tm["name"].(string)
			ev.Target.Namespace, _ = tm["namespace"].(string)
		}
	}
	path, _ := field("path")
	ev.Path, _ = path.(string)
	if hasFound && found != nil {
		ev.Found = report.ToYAML(report.Nest(ev.Path, found))
	}
	action, _ := field("action")
	ev.Action, _ = action.(string)
	if hasFix && fix != nil {
		fm, _ := fix.(map[string]any)
		if _, isManifest := fm["apiVersion"]; isManifest && fm["kind"] != nil {
			// A full manifest: replace the object if it is the same one, else create it.
			ev.Fix = report.ToYAML(fix)
			if ev.Action == "" {
				ev.Action = "create"
				md, _ := fm["metadata"].(map[string]any)
				if fm["kind"] == ev.Target.Kind && md["name"] == ev.Target.Name {
					ev.Action = "replace"
				}
			}
		} else {
			ev.Fix = report.ToYAML(report.Nest(ev.Path, fix))
			if ev.Action == "" {
				ev.Action = "patch"
			}
		}
	}
	ev.BuildCommand()
	return violation{message: ms, evidence: ev}, nil
}

// toNative converts a CEL value into plain Go values for YAML rendering.
func toNative(v ref.Val) any {
	switch t := v.(type) {
	case types.String:
		return string(t)
	case types.Int:
		return int64(t)
	case types.Uint:
		return uint64(t)
	case types.Double:
		return float64(t)
	case types.Bool:
		return bool(t)
	case types.Null:
		return nil
	case traits.Mapper:
		out := map[string]any{}
		it := t.Iterator()
		for it.HasNext() == types.True {
			k := it.Next()
			out[fmt.Sprint(k.Value())] = toNative(t.Get(k))
		}
		return out
	case traits.Lister:
		out := []any{}
		it := t.Iterator()
		for it.HasNext() == types.True {
			out = append(out, toNative(it.Next()))
		}
		return out
	}
	return v.Value()
}
