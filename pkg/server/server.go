// Package server is the broker's HTTP face: one exchange endpoint plus
// health and metrics.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/truvity/zitadel-ci-broker/pkg/githuboidc"
	"github.com/truvity/zitadel-ci-broker/pkg/mapping"
	"github.com/truvity/zitadel-ci-broker/pkg/mint"
)

// Deps wires the handler.
type Deps struct {
	Logger   *slog.Logger
	Verifier *githuboidc.Verifier
	Mapper   *mapping.Mapper
	Minter   mint.Minter
	// Minters holds per-provider implementations. A row naming a
	// provider present here uses it; anything else falls back to Minter,
	// which is the zitadel path every existing row takes.
	Minters map[string]mint.Minter
}

// minterFor picks the implementation for one resolved identity. Provider
// is a parameter of the same job -- verify, resolve, mint -- so the
// selection happens here rather than in a second endpoint.
func (d *Deps) minterFor(provider string) mint.Minter {
	if m, ok := d.Minters[provider]; ok && m != nil {
		return m
	}

	return d.Minter
}

// New builds the mux.
func New(deps *Deps) http.Handler {
	exchanges := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ci_broker_exchanges_total",
		Help: "Exchange requests by outcome and identity.",
	}, []string{"outcome", "user"})

	reg := prometheus.NewRegistry()
	reg.MustRegister(exchanges)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.Handle("POST /exchange", exchange(deps, exchanges))

	return mux
}

// exchange: bearer GitHub OIDC token in, Zitadel machine token out.
func exchange(deps *Deps, metric *prometheus.CounterVec) http.HandlerFunc {
	logger := deps.Logger

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" || raw == r.Header.Get("Authorization") {
			metric.WithLabelValues("no_token", "").Inc()
			httpError(w, http.StatusUnauthorized, "missing bearer token")

			return
		}

		claims, err := deps.Verifier.Verify(ctx, []byte(raw))
		if err != nil {
			logger.WarnContext(ctx, "token rejected", slog.Any("error", err))
			metric.WithLabelValues("rejected", "").Inc()
			httpError(w, http.StatusUnauthorized, "token rejected")

			return
		}

		// `?provider=` narrows resolution to rows of one provider. One
		// workflow legitimately needs two identities -- zitadel for its
		// kubeconfig and AWS credentials, cognito for the platform token
		// its tests present -- and both rows carry the same subject
		// pattern because it is the same workflow. Without the selector
		// the second row is unreachable by list order alone.
		//
		// Absent, resolution is exactly what it was.
		provider := r.URL.Query().Get("provider")

		identity, ok := deps.Mapper.ResolveFor(claims.Subject, provider)
		if !ok {
			// The refusal names the subject in logs, never in the
			// response — the caller learns nothing about the map.
			logger.WarnContext(ctx, "subject not mapped",
				slog.String("sub", claims.Subject),
				slog.String("repository", claims.Repository),
				slog.String("provider", provider),
			)
			metric.WithLabelValues("unmapped", "").Inc()
			httpError(w, http.StatusForbidden, "subject not mapped")

			return
		}

		tok, err := deps.minterFor(identity.Provider).Mint(ctx, identity.KeyFile, identity.Scopes)
		if err != nil {
			logger.ErrorContext(ctx, "mint failed",
				slog.String("user", identity.User),
				slog.Any("error", err),
			)
			metric.WithLabelValues("mint_error", identity.User).Inc()
			httpError(w, http.StatusBadGateway, "mint failed")

			return
		}

		logger.InfoContext(ctx, "token exchanged",
			slog.String("user", identity.User),
			slog.String("sub", claims.Subject),
			slog.String("run_id", claims.RunID),
			slog.Int64("expires_in", tok.ExpiresIn),
		)
		metric.WithLabelValues("ok", identity.User).Inc()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(tok)
	}
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
