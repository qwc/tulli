# syntax=docker/dockerfile:1

# --- build: compile the static binary from the vendored source (no network) ---
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
# vendor/ is present, so the build is fully offline and reproducible.
RUN CGO_ENABLED=0 go build -mod=vendor -o /out/tulli ./cmd/tulli

# --- runtime: the git server needs the real git (for git-http-backend, clone,
#     config, for-each-ref) plus gitleaks (fast lane, secrets) and trivy (deep
#     lane, SBOM/CVE). Trivy's vuln DB is pre-warmed into the image so the live
#     demo scans fast and offline (--skip-db-update at runtime). ---
FROM debian:bookworm-slim

ARG GITLEAKS_VERSION=8.21.2
ARG TRIVY_VERSION=0.58.1
ENV TRIVY_CACHE_DIR=/opt/trivy-cache
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates curl tar; \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      | tar -xz -C /usr/local/bin trivy; \
    gitleaks version; trivy --version; \
    # Pre-warm the vuln DB into the image cache, then make it world-readable.
    trivy --cache-dir "$TRIVY_CACHE_DIR" image --download-db-only; \
    chmod -R a+rX "$TRIVY_CACHE_DIR"; \
    apt-get purge -y curl; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*

# tulli clones file:// fixtures owned by the host user; neutralise git's
# "dubious ownership" guard for the demo (read-only mirrors, single-tenant box).
RUN git config --system --add safe.directory '*'

# Run unprivileged; /data (mirrors) is writable by the tulli user. Trivy also
# needs a writable scratch cache at runtime, so the pre-warmed DB is copied into
# the tulli-owned cache dir.
RUN useradd -r -u 10001 -m -d /home/tulli tulli && mkdir -p /data && chown tulli /data && chown -R tulli /opt/trivy-cache
COPY --from=build /out/tulli /usr/local/bin/tulli

USER tulli
ENV TULLI_ADDR=:8080 TULLI_DATA=/data
# 8080 git http-backend, 8081 web/API+UI, 2222 ssh (all opt-in via env/compose).
EXPOSE 8080 8081 2222
ENTRYPOINT ["tulli"]
