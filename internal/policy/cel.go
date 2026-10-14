package policy

import (
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
)

// costLimit bounds the work a single expression evaluation may do, so a
// badly written custom policy cannot stall a scan.
const costLimit = 10_000_000

// NewEnv returns the CEL environment every policy is compiled in.
//
// Variables available to expressions:
//
//	object      the Kubernetes object being evaluated
//	podSpec     its pod spec (Pods, workload templates, CronJob job templates), else null
//	podSpecPath where podSpec lives in object, e.g. "spec.template.spec" (else "")
//	containers  containers + initContainers + ephemeralContainers of podSpec
//	variables   the policy's own named variables
//	cluster     cross-resource context: clusterRoles, roles, networkPolicies,
//	            serviceAccounts, workloadCounts
func NewEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("podSpec", cel.DynType),
		cel.Variable("podSpecPath", cel.StringType),
		cel.Variable("containers", cel.ListType(cel.DynType)),
		cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("cluster", cel.DynType),
		cel.OptionalTypes(),
		ext.Strings(),
		ext.Sets(),
		ext.Lists(),
		ext.Bindings(),
		rbacLibrary(),
	)
}

// rbacLibrary adds `rules.allows(verb, apiGroup, resource)`, which answers
// "does this list of PolicyRules grant verb on apiGroup/resource?" with the
// same wildcard semantics as the Kubernetes RBAC authorizer ('*' verbs,
// groups and resources, and '*/subresource' wildcards).
func rbacLibrary() cel.EnvOption {
	return cel.Function("allows",
		cel.MemberOverload("list_allows_string_string_string",
			[]*cel.Type{cel.ListType(cel.DynType), cel.StringType, cel.StringType, cel.StringType},
			cel.BoolType,
			cel.FunctionBinding(func(args ...ref.Val) ref.Val {
				verb, _ := args[1].(types.String)
				group, _ := args[2].(types.String)
				resource, _ := args[3].(types.String)
				return types.Bool(rulesAllow(args[0], string(verb), string(group), string(resource)))
			}),
		),
	)
}

func rulesAllow(rules ref.Val, verb, group, resource string) bool {
	list, ok := rules.(traits.Lister)
	if !ok {
		return false
	}
	it := list.Iterator()
	for it.HasNext() == types.True {
		rule, ok := it.Next().(traits.Mapper)
		if !ok {
			continue
		}
		if contains(stringList(rule, "verbs"), verb) &&
			contains(stringList(rule, "apiGroups"), group) &&
			resourceMatches(stringList(rule, "resources"), resource) {
			return true
		}
	}
	return false
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == "*" || v == want {
			return true
		}
	}
	return false
}

func resourceMatches(values []string, want string) bool {
	for _, v := range values {
		switch {
		case v == "*", v == want:
			return true
		case strings.HasPrefix(v, "*/") && strings.Contains(want, "/") && strings.HasSuffix(want, v[1:]):
			return true // e.g. "*/scale" covers "deployments/scale"
		}
	}
	return false
}

func stringList(m traits.Mapper, key string) []string {
	v, found := m.Find(types.String(key))
	if !found {
		return nil
	}
	list, ok := v.(traits.Lister)
	if !ok {
		return nil
	}
	var out []string
	it := list.Iterator()
	for it.HasNext() == types.True {
		if s, ok := it.Next().(types.String); ok {
			out = append(out, string(s))
		}
	}
	return out
}
