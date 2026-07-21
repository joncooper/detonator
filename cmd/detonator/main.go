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
	"syscall"
	"time"

	"github.com/joncooper/detonator/internal/cache"
	"github.com/joncooper/detonator/internal/config"
	"github.com/joncooper/detonator/internal/gate"
	"github.com/joncooper/detonator/internal/proxy"
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

	srv := proxy.New(cfg, c, gate.AllowAll{}, log)
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
			"gate", "allow-all (phase 1)")
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
