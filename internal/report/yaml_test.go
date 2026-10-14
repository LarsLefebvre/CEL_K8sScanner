package report

import "testing"

func TestToYAML(t *testing.T) {
	v := Nest("spec.template.spec", map[string]any{
		"containers": []any{map[string]any{
			"securityContext": map[string]any{"privileged": false, "runAsUser": int64(1000)},
			"name":            "app",
			"image":           "busybox:<version>@sha256:<digest>",
		}},
		"volumes": []any{map[string]any{"name": "data", "hostPath": nil, "emptyDir": map[string]any{}}},
	})
	want := `spec:
  template:
    spec:
      containers:
        - name: app
          image: "busybox:<version>@sha256:<digest>"
          securityContext:
            privileged: false
            runAsUser: 1000
      volumes:
        - name: data
          emptyDir: {}
          hostPath: null
`
	if got := ToYAML(v); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	for _, s := range []string{"true", "on", "123", "", "a: b", "#x"} {
		if !needsQuotes(s) {
			t.Errorf("%q should be quoted", s)
		}
	}
}
