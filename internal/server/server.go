// Package server runs kscan as a long-lived service: periodic scans, a web
// dashboard, a JSON API, Prometheus metrics and a CEL policy playground.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/larslefebvre/kscan/internal/collector"
	"github.com/larslefebvre/kscan/internal/inventory"
	"github.com/larslefebvre/kscan/internal/policy"
	"github.com/larslefebvre/kscan/internal/report"
)

//go:embed ui/index.html
var ui embed.FS

type Config struct {
	Collect  func(context.Context) (*inventory.Inventory, error)
	Engine   func() (*policy.Engine, error) // called before every scan, so policy changes hot-reload
	Excludes []string
	Interval time.Duration
}

type Server struct {
	cfg     Config
	trigger chan struct{}

	mu        sync.RWMutex
	engine    *policy.Engine // last engine that compiled
	inv       *inventory.Inventory
	report    *report.Report
	scanning  bool
	lastError string
	policyErr string
}

type status struct {
	Scanning    bool      `json:"scanning"`
	LastScan    time.Time `json:"lastScan,omitempty"`
	NextScan    time.Time `json:"nextScan,omitempty"`
	LastError   string    `json:"lastError,omitempty"`
	PolicyError string    `json:"policyError,omitempty"`
	Interval    string    `json:"interval"`
}

func New(cfg Config) *Server {
	return &Server{cfg: cfg, trigger: make(chan struct{}, 1)}
}

func (s *Server) Run(ctx context.Context, addr string) error {
	httpSrv := &http.Server{Addr: addr, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", addr)
		errc <- httpSrv.ListenAndServe()
	}()
	go s.loop(ctx)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

func (s *Server) loop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	s.scan(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.trigger:
			ticker.Reset(s.cfg.Interval)
		}
		s.scan(ctx)
	}
}

func (s *Server) scan(ctx context.Context) {
	s.mu.Lock()
	s.scanning = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.scanning = false
		s.mu.Unlock()
	}()

	eng, err := s.cfg.Engine()
	s.mu.Lock()
	if err != nil {
		slog.Error("policy reload failed, keeping previous policies", "err", err)
		s.policyErr = err.Error()
		eng = s.engine
	} else {
		s.policyErr = ""
		s.engine = eng
	}
	s.mu.Unlock()
	if eng == nil {
		return
	}

	inv, err := s.cfg.Collect(ctx)
	if err != nil {
		slog.Error("collection failed", "err", err)
		s.mu.Lock()
		s.lastError = err.Error()
		s.mu.Unlock()
		return
	}
	rep := eng.Scan(inv)
	slog.Info("scan complete",
		"objects", rep.ObjectsScanned, "findings", rep.Summary.Total,
		"critical", rep.Summary.BySeverity[report.Critical], "high", rep.Summary.BySeverity[report.High],
		"score", rep.Summary.Score, "duration_ms", rep.DurationMs, "policy_errors", len(rep.PolicyErrors))

	s.mu.Lock()
	s.inv, s.report, s.lastError = inv, rep, ""
	s.mu.Unlock()
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data, _ := ui.ReadFile("ui/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache") // always pick up a new UI after a redeploy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		ready := s.engine != nil
		s.mu.RUnlock()
		if !ready {
			http.Error(w, "policies not loaded", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		rep := s.report
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		report.WriteMetrics(w, rep)
	})
	mux.HandleFunc("GET /api/report", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		rep := s.report
		s.mu.RUnlock()
		if rep == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no scan completed yet"})
			return
		}
		writeJSON(w, http.StatusOK, rep)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		st := status{Scanning: s.scanning, LastError: s.lastError, PolicyError: s.policyErr, Interval: s.cfg.Interval.String()}
		if s.report != nil {
			st.LastScan = s.report.GeneratedAt
			st.NextScan = s.report.GeneratedAt.Add(s.cfg.Interval)
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, st)
	})
	mux.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.trigger <- struct{}{}:
		default: // a scan is already queued
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "scan queued"})
	})
	mux.HandleFunc("GET /api/policies", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		eng := s.engine
		s.mu.RUnlock()
		if eng == nil {
			writeJSON(w, http.StatusOK, []policy.Policy{})
			return
		}
		writeJSON(w, http.StatusOK, eng.Policies())
	})
	mux.HandleFunc("POST /api/playground", s.playground)
	return mux
}

type playgroundRequest struct {
	Policy    string `json:"policy"`    // one or more policies as YAML
	Manifests string `json:"manifests"` // optional YAML; empty = latest cluster inventory
}

// playground compiles ad-hoc policies and evaluates them against pasted
// manifests or the live inventory from the latest scan. Expressions run
// under the same CEL cost limit as regular policies.
func (s *Server) playground(w http.ResponseWriter, r *http.Request) {
	var req playgroundRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	ps, err := policy.Parse([]byte(req.Policy), "playground")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(ps) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no policy found"})
		return
	}

	var inv *inventory.Inventory
	var excludes []string
	if req.Manifests != "" {
		inv = inventory.New("playground manifests")
		inv.Cluster.Name = "pasted manifests"
		if err := collector.AddManifests(inv, []byte(req.Manifests)); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "manifests: " + err.Error()})
			return
		}
	} else {
		s.mu.RLock()
		inv = s.inv
		s.mu.RUnlock()
		if inv == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no cluster inventory yet; paste manifests or wait for the first scan"})
			return
		}
		excludes = s.cfg.Excludes
	}

	eng, err := policy.NewEngine(ps, policy.Options{ExcludeNamespaces: excludes})
	if err != nil {
		var ce *policy.CompileError
		if errors.As(err, &ce) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": ce.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, eng.Scan(inv))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
