# syntax=docker/dockerfile:1

# --- build: compile the static binary from the vendored source (no network) ---
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
# vendor/ is present, so the build is fully offline and reproducible.
RUN CGO_ENABLED=0 go build -mod=vendor -o /out/tulli ./cmd/tulli

# --- runtime: the git server needs the real git (for git-http-backend, clone,
#     config, for-each-ref) plus gitleaks (the secret scanner the worker shells). ---
FROM debian:bookworm-slim

ARG GITLEAKS_VERSION=8.21.2
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates curl; \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    apt-get purge -y curl; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*; \
    gitleaks version

# tulli clones file:// fixtures owned by the host user; neutralise git's
# "dubious ownership" guard for the demo (read-only mirrors, single-tenant box).
RUN git config --system --add safe.directory '*'

# Run unprivileged; /data (mirrors) is writable by the tulli user.
RUN useradd -r -u 10001 -m -d /home/tulli tulli && mkdir -p /data && chown tulli /data
COPY --from=build /out/tulli /usr/local/bin/tulli

USER tulli
ENV TULLI_ADDR=:8080 TULLI_DATA=/data
EXPOSE 8080
ENTRYPOINT ["tulli"]
