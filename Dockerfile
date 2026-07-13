# syntax=docker/dockerfile:1

# --- build: compile the static binary from the vendored source (no network) ---
FROM golang:1.26-trixie AS build
WORKDIR /src
# Corporate TLS-inspecting proxy (Zscaler et al.)? Any PEM .crt roots dropped
# into certs/ are trusted here too. The vendored build below needs no network,
# but this keeps the build honest if you ever build without vendor/. Empty by
# default (just a .keep), so it's a no-op unless you add certs. See certs/README.md.
COPY certs/ /usr/local/share/ca-certificates/tulli/
RUN update-ca-certificates
COPY . .
# vendor/ is present, so the build is fully offline and reproducible.
RUN CGO_ENABLED=0 go build -mod=vendor -o /out/tulli ./cmd/tulli

# --- runtime: the git server needs the real git (for git-http-backend, clone,
#     config, for-each-ref) plus gitleaks (fast lane, secrets) and trivy (deep
#     lane, SBOM/CVE). Trivy's vuln DB is pre-warmed into the image so the live
#     demo scans fast and offline (--skip-db-update at runtime). ---
FROM debian:trixie-slim

ARG GITLEAKS_VERSION=8.21.2
# NOTE: Aqua purged the prebuilt release binaries from every trivy tag < 0.70.0
# (only the source archive remains), so older pins 404. v0.70.0 is the earliest
# still-downloadable Linux-64bit binary. Keep this at a version that actually
# ships a binary, or the build breaks at the curl below.
ARG TRIVY_VERSION=0.72.0
ENV TRIVY_CACHE_DIR=/opt/trivy-cache
# Locked-down network with an internal Debian mirror instead of deb.debian.org?
# Pass --build-arg APT_MIRROR=http://apt.corp/debian (matches the CDN layout:
# <base>/debian + <base>/debian-security). Keep it HTTP if you can — Debian
# packages are GPG-signed (Signed-By keyring), so the transport needs no TLS
# trust and this stays a clean bootstrap. An HTTPS mirror with a corporate CA
# is a chicken-and-egg on -slim (no ca-certificates yet), so prefer HTTP or a
# publicly-trusted cert for the mirror itself.
ARG APT_MIRROR=
# Base packages. Debian's default apt talks HTTP, so this succeeds even behind a
# TLS-inspecting proxy before our custom roots are installed. It also brings in
# ca-certificates + update-ca-certificates, needed for the cert step below.
RUN set -eux; \
    if [ -n "$APT_MIRROR" ]; then \
      sed -i "s#http://deb.debian.org#${APT_MIRROR%/debian}#g" /etc/apt/sources.list.d/debian.sources; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates curl tar

# Corporate root CAs (Zscaler et al.): every PEM .crt dropped into certs/ is
# installed into the system trust store, so the HTTPS downloads below AND tulli's
# runtime git clones / trivy DB refreshes trust the proxy. Must land before the
# first HTTPS curl. Empty by default (a .keep) ⇒ no-op. See certs/README.md.
COPY certs/ /usr/local/share/ca-certificates/tulli/
RUN update-ca-certificates

# -f makes curl fail on an HTTP error instead of streaming GitHub's "Not Found"
# page into tar (which surfaces as a baffling "not in gzip format"); we download
# to a file first so a failed curl aborts the layer before tar ever runs (the
# default /bin/sh here is dash, which has no `set -o pipefail`).
RUN set -eux; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm -f /tmp/gitleaks.tar.gz /tmp/trivy.tar.gz; \
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
