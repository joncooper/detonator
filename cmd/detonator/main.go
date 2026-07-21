// Command detonator runs the admission-gate proxy: a caching pull-through
// registry for npm and PyPI. In Phase 1 the gate admits everything, so the
// proxy can be proven a transparent drop-in before real analysis is wired.
//
// Point tooling at it:
//
//	npm:  npm config set registry http://127.0.0.1:8080/npm/
//	pip:  pip install --index-url http://127.0.0.1:8080/pypi/simple/ <pkg>
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/joncooper/detonator/internal/analyze/osv"
	"github.com/joncooper/detonator/internal/cache"
	"github.com/joncooper/detonator/internal/config"
	"github.com/joncooper/detonator/internal/engine"
	"github.com/joncooper/detonator/internal/gate"
	"github.com/joncooper/detonator/internal/proxy"
	"github.com/joncooper/detonator/internal/sign"
	"github.com/joncooper/detonator/internal/triage"
)

func main() {
	cfg := config.Default()
	var logLevel string
	flag.StringVar(&cfg.Listen, "listen", cfg.Listen, "address to bind")
	flag.StringVar(&cfg.PublicURL, "public-url", cfg.PublicURL, "how clients reach this proxy (for URL rewriting)")
	flag.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "on-disk cache root")
	flag.StringVar(&cfg.NPMUpstream, "npm-upstream", cfg.NPMUpstream, "npm registry upstream")
	flag.StringVar(&cfg.PyPISimpleUpstream, "pypi-simple-upstream", cfg.PyPISimpleUpstream, "PyPI simple index upstream")
	flag.StringVar(&cfg.PyPIFilesUpstream, "pypi-files-upstream", cfg.PyPIFilesUpstream, "PyPI file host upstream")
	flag.IntVar(&cfg.MetadataTTLSeconds, "metadata-ttl", cfg.MetadataTTLSeconds, "seconds to serve cached metadata before revalidating")
	flag.StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	gateKind := flag.String("gate", "static", "admission gate: 'static' (analyze) or 'allow-all' (transparent stub)")
	osvURL := flag.String("osv-url", "https://api.osv.dev", "OSV API base URL")
	enableOSV := flag.Bool("osv", true, "enable OSV known-vuln lookup")
	failClosed := flag.Bool("fail-closed", false, "block on uncertainty instead of quarantining for review")
	triageKind := flag.String("triage", "off", "LLM triage: 'off', 'mock' (local), or 'codex' (sends source to OpenAI)")
	triageModel := flag.String("triage-model", "gpt-5.6-sol-medium", "codex model tier for triage")
	triageSchema := flag.String("triage-schema", "phase0/verdict-schema.json", "output schema for codex triage")
	doSign := flag.Bool("sign", true, "sign cached verdicts so they can't be forged")
	signingKey := flag.String("signing-key", "", "path to ed25519 signing key (default: <cache-dir>/signing-key)")
	flag.Parse()

	log := newLogger(logLevel)

	if err := cfg.Validate(); err != nil {
		log.Error("invalid config", "err", err)
		os.Exit(2)
	}

	c, err := cache.New(cfg.CacheDir, time.Duration(cfg.MetadataTTLSeconds)*time.Second)
	if err != nil {
		log.Error("cache init failed", "err", err)
		os.Exit(1)
	}

	if *doSign {
		keyPath := *signingKey
		if keyPath == "" {
			keyPath = filepath.Join(cfg.CacheDir, "signing-key")
		}
		signer, err := sign.LoadOrCreateEd25519(keyPath)
		if err != nil {
			log.Error("signing key init failed", "err", err)
			os.Exit(1)
		}
		c.SetSigner(signer)
		log.Info("verdict signing enabled", "key_id", signer.KeyID(), "alg", signer.Algorithm())
	}

	model := buildModel(*triageKind, *triageModel, *triageSchema, log)
	g := buildGate(*gateKind, c, *osvURL, *enableOSV, *failClosed, model, log)
	srv := proxy.New(cfg, c, g, log)
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("detonator proxy listening",
			"addr", cfg.Listen,
			"public_url", cfg.PublicURL,
			"npm_registry", cfg.PublicURL+"/npm/",
			"pypi_index", cfg.PublicURL+"/pypi/simple/",
			"gate", *gateKind)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown error", "err", err)
	}
}

// buildGate constructs the admission gate selected on the command line.
func buildGate(kind string, c *cache.Cache, osvURL string, enableOSV, failClosed bool, model triage.Model, log *slog.Logger) gate.Gate {
	if kind == "allow-all" {
		log.Warn("gate is allow-all: every package is admitted without analysis")
		return gate.AllowAll{}
	}
	opts := gate.PipelineOptions{
		Cache:  c,
		Model:  model,
		Policy: engine.Policy{FailClosed: failClosed},
		Logger: log,
	}
	if enableOSV {
		opts.OSV = osv.New(osvURL)
	}
	return gate.NewPipeline(opts)
}

// buildModel constructs the triage model selected on the command line. The
// codex path sends package source to a third party, so it is opt-in and warns.
func buildModel(kind, modelName, schemaPath string, log *slog.Logger) triage.Model {
	switch kind {
	case "off", "":
		return nil
	case "mock":
		log.Info("triage: local mock model (no source leaves this machine)")
		return triage.MockModel{}
	case "codex":
		log.Warn("triage: codex model ENABLED — package source will be sent to OpenAI", "model", modelName)
		return triage.NewCodex(schemaPath, modelName)
	default:
		log.Warn("unknown triage kind, disabling", "kind", kind)
		return nil
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
