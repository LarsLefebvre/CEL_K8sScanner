// kscan is a Kubernetes misconfiguration and RBAC risk scanner driven by CEL
// policies. It runs as a one-shot CLI (against a cluster or manifest files)
// or as an in-cluster service with a web UI, JSON API and Prometheus metrics.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/larslefebvre/kscan/internal/collector"
	"github.com/larslefebvre/kscan/internal/inventory"
	"github.com/larslefebvre/kscan/internal/policy"
	"github.com/larslefebvre/kscan/internal/report"
	"github.com/larslefebvre/kscan/internal/server"
	"github.com/larslefebvre/kscan/policies"
)

const defaultExcludes = "kube-system,kube-public,kube-node-lease,local-path-storage"

const usage = `kscan - CEL-based Kubernetes security scanner

Usage:
  kscan scan     [flags]   scan a cluster (or manifest files) once and print a report
  kscan serve    [flags]   run continuously: web UI, JSON API, /metrics, policy playground
  kscan policies [flags]   list the loaded policies

Run 'kscan <command> -h' for flags.
`

// common holds flags shared by every subcommand.
type common struct {
	kubeconfig  string
	kubeContext string
	clusterName string
	files       string
	policyDir   string
	noBuiltin   bool
	excludes    string
	logLevel    string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: in-cluster config, then $KUBECONFIG / ~/.kube/config)")
	fs.StringVar(&c.kubeContext, "context", "", "kubeconfig context to use")
	fs.StringVar(&c.clusterName, "cluster-name", os.Getenv("KSCAN_CLUSTER_NAME"), "display name for the cluster (default: kubeconfig context, or \"in-cluster\")")
	fs.StringVar(&c.files, "files", "", "comma-separated manifest files/dirs to scan instead of a live cluster")
	fs.StringVar(&c.policyDir, "policies", "", "directory of additional/overriding policy YAML files")
	fs.BoolVar(&c.noBuiltin, "no-builtin", false, "do not load the built-in policy library")
	fs.StringVar(&c.excludes, "exclude-namespaces", envOr("KSCAN_EXCLUDE_NAMESPACES", defaultExcludes), "comma-separated namespaces to skip")
	fs.StringVar(&c.logLevel, "log-level", "info", "debug|info|warn|error")
}

func (c *common) setupLogging(w *os.File) {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(c.logLevel))
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl})))
}

func (c *common) loadPolicies() ([]policy.Policy, error) {
	var sets [][]policy.Policy
	if !c.noBuiltin {
		builtin, err := policy.LoadFS(policies.Builtin, "builtin")
		if err != nil {
			return nil, fmt.Errorf("built-in policies: %w", err)
		}
		sets = append(sets, builtin)
	}
	if c.policyDir != "" {
		custom, err := policy.LoadDir(c.policyDir)
		switch {
		case errors.Is(err, os.ErrNotExist):
			slog.Warn("policy directory not found, using built-in policies only", "dir", c.policyDir)
		case err != nil:
			return nil, err
		default:
			sets = append(sets, custom)
		}
	}
	return policy.Merge(sets...), nil
}

func (c *common) engine() (*policy.Engine, error) {
	ps, err := c.loadPolicies()
	if err != nil {
		return nil, err
	}
	excludes := splitList(c.excludes)
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		excludes = append(excludes, ns) // don't scan ourselves
	}
	return policy.NewEngine(ps, policy.Options{ExcludeNamespaces: excludes})
}

// collect returns a function producing a fresh inventory per call.
func (c *common) collect() (func(context.Context) (*inventory.Inventory, error), error) {
	if c.files != "" {
		paths := splitList(c.files)
		return func(context.Context) (*inventory.Inventory, error) { return collector.FromFiles(paths...) }, nil
	}
	cfg, err := collector.RESTConfig(c.kubeconfig, c.kubeContext)
	if err != nil {
		return nil, fmt.Errorf("kubernetes config: %w (use --files to scan manifests without a cluster)", err)
	}
	cl, err := collector.NewCluster(cfg, collector.ClusterName(c.clusterName, c.kubeconfig, c.kubeContext))
	if err != nil {
		return nil, err
	}
	return cl.Collect, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	code := 0
	switch os.Args[1] {
	case "scan":
		code, err = runScan(ctx, os.Args[2:])
	case "serve":
		err = runServe(ctx, os.Args[2:])
	case "policies":
		err = runPolicies(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		code = 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		code = 1
	}
	os.Exit(code)
}

func runScan(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var c common
	c.register(fs)
	output := fs.String("output", "table", "table|json")
	failOn := fs.String("fail-on", "", "exit with code 3 if any finding is at or above this severity (for CI)")
	minSev := fs.String("min-severity", "info", "only report findings at or above this severity")
	noColor := fs.Bool("no-color", os.Getenv("NO_COLOR") != "", "disable ANSI colors in table output")
	_ = fs.Parse(args)
	c.setupLogging(os.Stderr)

	eng, err := c.engine()
	if err != nil {
		return 0, err
	}
	collect, err := c.collect()
	if err != nil {
		return 0, err
	}
	inv, err := collect(ctx)
	if err != nil {
		return 0, err
	}
	rep := eng.Scan(inv)

	min, err := report.ParseSeverity(*minSev)
	if err != nil {
		return 0, err
	}
	if min != report.Info {
		kept := rep.Findings[:0]
		for _, f := range rep.Findings {
			if f.Severity.Rank() >= min.Rank() {
				kept = append(kept, f)
			}
		}
		rep.Findings = kept
		rep.Finalize()
	}

	switch *output {
	case "json":
		if err := report.WriteJSON(os.Stdout, rep); err != nil {
			return 0, err
		}
	case "table":
		report.WriteTable(os.Stdout, rep, !*noColor && isTerminal(os.Stdout))
	default:
		return 0, fmt.Errorf("unknown output %q", *output)
	}

	if *failOn != "" {
		sev, err := report.ParseSeverity(*failOn)
		if err != nil {
			return 0, err
		}
		if n := rep.CountAtOrAbove(sev); n > 0 {
			fmt.Fprintf(os.Stderr, "%d findings at or above %s\n", n, sev)
			return 3, nil
		}
	}
	return 0, nil
}

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var c common
	c.register(fs)
	listen := fs.String("listen", ":8080", "HTTP listen address")
	interval := fs.Duration("interval", 5*time.Minute, "time between scans")
	_ = fs.Parse(args)
	c.setupLogging(os.Stderr)

	// Fail fast on broken policies at startup; later reloads keep the last
	// good engine if a policy edit doesn't compile.
	if _, err := c.engine(); err != nil {
		return err
	}
	collect, err := c.collect()
	if err != nil {
		return err
	}
	srv := server.New(server.Config{
		Collect:  collect,
		Engine:   c.engine,
		Excludes: splitList(c.excludes),
		Interval: *interval,
	})
	return srv.Run(ctx, *listen)
}

func runPolicies(args []string) error {
	fs := flag.NewFlagSet("policies", flag.ExitOnError)
	var c common
	c.register(fs)
	_ = fs.Parse(args)
	c.setupLogging(os.Stderr)

	eng, err := c.engine()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "POLICY\tSEVERITY\tTACTIC\tMITRE ATT&CK\tTHREAT MATRIX")
	for _, p := range eng.Policies() {
		var tm []string
		for _, t := range p.MatrixTechniques {
			tm = append(tm, t.Tactic+" › "+t.Name)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.Severity, p.Tactic, strings.Join(p.MITRE, ", "), strings.Join(tm, ", "))
	}
	return tw.Flush()
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
