# Corporate root CAs (for TLS-inspecting proxies)

If you build or run tulli behind a TLS-inspecting proxy — Zscaler, Netskope, a
corporate MITM gateway — the proxy presents **its own root certificate** in place
of the real upstream one. Nothing here will trust it out of the box, so:

- the **image build** fails when it fetches `gitleaks`/`trivy` from GitHub over
  HTTPS and when trivy downloads its vuln DB, and
- **serving** fails when tulli shells out to `git clone`/`fetch` against HTTPS
  upstreams (and when trivy refreshes its DB).

## How to use

Drop your proxy's root CA — and any internal roots you need — into this
directory as **PEM-encoded files with a `.crt` extension**, one cert per file:

```sh
cp /path/to/zscaler-root.crt   certs/
cp /path/to/internal-root.crt  certs/
docker compose build           # or: docker build .
```

The `Dockerfile` copies every `certs/*.crt` into the system trust store
(`/usr/local/share/ca-certificates/tulli/`) and runs `update-ca-certificates` in
**both** build stages. That one install is trusted by `git`, `curl`, `trivy`, and
Go (the binary is built `CGO_ENABLED=0` and reads the system bundle), so it
covers the HTTPS downloads *during the build* and tulli's upstream fetches *at
runtime*. No certs here ⇒ the step is a harmless no-op.

## Notes

- Files must be **PEM** (the `-----BEGIN CERTIFICATE-----` text form) with a
  `.crt` extension — that's what `update-ca-certificates` picks up. If yours is
  DER/`.cer`, convert it: `openssl x509 -inform der -in in.cer -out out.crt`.
- Include the **root** (and any intermediates) of the inspection chain, not the
  per-site leaf your proxy mints.
- These files are **git-ignored** (see `.gitignore`) so you don't accidentally
  commit your organisation's internal CA. Only this README and a `.keep`
  placeholder are tracked.
- The proxy CA fixes *trust*. If your proxy is an **explicit** (non-transparent)
  proxy you must also point traffic at it — set `HTTP_PROXY`/`HTTPS_PROXY`
  (`--build-arg` at build time, and in `docker-compose.yml` for the running
  service). See the commented block in `docker-compose.yml`.
