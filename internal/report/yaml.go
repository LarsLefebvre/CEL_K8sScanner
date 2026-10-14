package report

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// keyOrder puts the fields people expect first; everything else is sorted.
var keyOrder = map[string]int{"apiVersion": 0, "kind": 1, "metadata": 2, "name": 3, "namespace": 4}

// ToYAML renders a decoded JSON-like value (maps, slices, scalars) as YAML
// with Kubernetes-friendly key order (apiVersion, kind, metadata, name first).
func ToYAML(v any) string {
	var b strings.Builder
	writeYAML(&b, v, 0, false)
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		oi, iok := keyOrder[keys[i]]
		oj, jok := keyOrder[keys[j]]
		switch {
		case iok && jok:
			return oi < oj
		case iok != jok:
			return iok
		}
		return keys[i] < keys[j]
	})
	return keys
}

// writeYAML writes v at the given indent. inList means the first line is
// already prefixed by "- " and must not be indented again.
func writeYAML(b *strings.Builder, v any, indent int, inList bool) {
	pad := strings.Repeat("  ", indent)
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			b.WriteString("{}\n")
			return
		}
		for i, k := range sortedKeys(t) {
			if i > 0 || !inList {
				b.WriteString(pad)
			}
			b.WriteString(scalar(k) + ":")
			writeChild(b, t[k], indent)
		}
	case []any:
		if len(t) == 0 {
			b.WriteString("[]\n")
			return
		}
		for i, el := range t {
			if i > 0 || !inList {
				b.WriteString(pad)
			}
			b.WriteString("- ")
			if isComposite(el) && !isEmpty(el) {
				writeYAML(b, el, indent+1, true)
			} else {
				b.WriteString(scalar(el) + "\n")
			}
		}
	default:
		b.WriteString(scalar(v) + "\n")
	}
}

func writeChild(b *strings.Builder, v any, indent int) {
	switch {
	case !isComposite(v) || isEmpty(v):
		b.WriteString(" ")
		writeYAML(b, v, 0, true)
	case isList(v):
		// Lists under a key are indented one level (kubectl style).
		b.WriteString("\n")
		writeYAML(b, v, indent+1, false)
	default:
		b.WriteString("\n")
		writeYAML(b, v, indent+1, false)
	}
}

func isComposite(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func isList(v any) bool { _, ok := v.([]any); return ok }

func isEmpty(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}

var plainString = regexp.MustCompile(`^[A-Za-z0-9_./][A-Za-z0-9_./ :@+\-]*$`)

func scalar(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case string:
		if needsQuotes(t) {
			return strconv.Quote(t)
		}
		return t
	case map[string]any, []any:
		return "{}"
	}
	return strconv.Quote(fmt.Sprint(v))
}

func needsQuotes(s string) bool {
	if s == "" || !plainString.MatchString(s) || strings.HasSuffix(s, " ") || strings.Contains(s, ": ") || strings.HasSuffix(s, ":") {
		return true
	}
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off", "null", "~", "y", "n":
		return true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	return false
}

// Nest wraps v under a dotted path, e.g. Nest("spec.template.spec", x) ->
// {spec: {template: {spec: x}}}. An empty path returns v unchanged.
func Nest(path string, v any) any {
	if path == "" {
		return v
	}
	parts := strings.Split(path, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		v = map[string]any{parts[i]: v}
	}
	return v
}
