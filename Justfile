# Development commands for zitadel-ci-broker

# Disable go.work (parent workspace interferes with standalone module builds)
export GOWORK := "off"

# Format all Go files (gofmt + goimports via golangci-lint)
fmt:
    golangci-lint fmt ./...

# Build all binaries
build: fmt
    go build -o bin/zitadel-ci-broker ./cmd/broker/

# Run unit tests
test:
    go test ./... -coverprofile=coverage.out


# Run linters
lint:
    golangci-lint run ./...

# Run Go vulnerability check
vuln:
    govulncheck ./...

# Run go mod tidy
tidy:
    go mod tidy

# Clean build artifacts
clean:
    rm -rf bin/ dist/ coverage.out

# Run all checks (build + unit tests + integration tests + lint + vuln)
# Render the chart with representative values; prove the schema rejects
# an unknown key (values.schema.json is the contract — a typo must fail
# the render, not be silently ignored).
chart-lint:
    helm lint charts/zitadel-ci-broker
    helm template zitadel-ci-broker charts/zitadel-ci-broker \
        --set image.tag=0.0.0 \
        --set keysSecretName=example-keys >/dev/null
    ! helm template zitadel-ci-broker charts/zitadel-ci-broker --set bogusKey=1 >/dev/null 2>&1

check: build test lint chart-lint vuln

# Build a snapshot release locally (no push, no tag)
snapshot:
    goreleaser release --snapshot --clean

# Package Helm chart locally
helm-package:
    helm package charts/zitadel-ci-broker --destination dist/
