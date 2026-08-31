// zitadel-ci-broker exchanges GitHub Actions OIDC tokens for Zitadel
// machine-user tokens — workload identity federation as a service,
// until Zitadel ships it natively.
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

	"github.com/truvity/zitadel-ci-broker/pkg/config"
	"github.com/truvity/zitadel-ci-broker/pkg/githuboidc"
	"github.com/truvity/zitadel-ci-broker/pkg/mapping"
	"github.com/truvity/zitadel-ci-broker/pkg/mint"
	"github.com/truvity/zitadel-ci-broker/pkg/server"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if err := run(ctx, logger); err != nil {
		logger.ErrorContext(ctx, "fatal", slog.Any("error", err))
		cancel()
		os.Exit(1) //nolint:gocritic // intentional exit after logging
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	var configPath string

	flag.StringVar(&configPath, "config", "/etc/zitadel-ci-broker/config.yaml", "config file path")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	verifier, err := githuboidc.New(ctx, cfg.GitHub.Issuer, cfg.GitHub.Audience)
	if err != nil {
		return err
	}

	mapper, err := mapping.New(cfg.Identities)
	if err != nil {
		return err
	}

	handler := server.New(&server.Deps{
		Logger:   logger,
		Verifier: verifier,
		Mapper:   mapper,
		Minter:   &mint.JWTProfileMinter{Domain: cfg.Zitadel.Domain},
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.InfoContext(ctx, "listening",
		slog.String("addr", cfg.Listen),
		slog.String("issuer", cfg.GitHub.Issuer),
		slog.String("audience", cfg.GitHub.Audience),
		slog.Int("identities", len(cfg.Identities)),
	)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}
