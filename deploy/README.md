# Deploying redactr-server

This directory contains everything needed to run the Redactr control-plane
server in production: a distroless container image, a [Caddy](https://caddyserver.com)
reverse proxy that terminates TLS (automatic ACME / Let's Encrypt certificates),
and a `docker compose` stack that wires them together with durable volumes.

## Architecture

```
internet ──443──> caddy (TLS, ACME) ──http:8080──> redactr-server
```

Caddy obtains and renews the certificate for your domain automatically. The
redactr-server process speaks plain HTTP on port 8080 inside the Docker network;
it is never exposed directly to the internet. TLS is terminated at Caddy.

## Quickstart

```sh
cp .env.example .env
# edit .env — at minimum set REDACTR_DOMAIN and a superadmin hash and/or OIDC
docker compose up -d
docker compose logs -f redactr-server
```

Point your domain's DNS A/AAAA record at the host first, and make sure ports
80 and 443 are open — Caddy needs them to complete the ACME challenge.

The server fails fast on startup if the configuration is invalid in production
(missing https public URL, no auth method, unparseable durations/numbers, etc.).
Read the logs if the container exits immediately.

## Generating a bcrypt password hash

`REDACTR_SUPERADMIN_PASSWORD_HASH` must be a bcrypt hash (cost 12 recommended).
Generate one without committing plaintext:

```sh
# Using htpasswd (apache2-utils / httpd-tools):
htpasswd -bnBC 12 "" 'your-password' | tr -d ':\n'

# Or via Docker if htpasswd isn't installed locally:
docker run --rm httpd:2 htpasswd -bnBC 12 "" 'your-password' | tr -d ':\n'
```

Go one-liner alternative:

```sh
go run - <<'EOF'
package main
import ("fmt"; "golang.org/x/crypto/bcrypt")
func main() { h,_ := bcrypt.GenerateFromPassword([]byte("your-password"), 12); fmt.Println(string(h)) }
EOF
```

Paste the output into `REDACTR_SUPERADMIN_PASSWORD_HASH`. (You may instead set
`REDACTR_SUPERADMIN_PASSWORD` to a plaintext value; the server will hash it at
startup and log a warning recommending the hash form. Prefer the hash.)

## OIDC single sign-on (optional)

Set all three of `REDACTR_OIDC_ISSUER`, `REDACTR_OIDC_CLIENT_ID`, and
`REDACTR_OIDC_CLIENT_SECRET` to enable SSO. The redirect URL defaults to:

```
https://<REDACTR_DOMAIN>/admin/oidc/callback
```

Register that exact URL with your identity provider. Override it with
`REDACTR_OIDC_REDIRECT_URL` only if your setup requires a different callback.

You can configure superadmin password login, OIDC, or both. At least one auth
method is required in production.

## Volumes and state

Three named volumes hold durable state (see `docker-compose.yml`):

| Volume             | Mount path     | Contents                                  |
|--------------------|----------------|-------------------------------------------|
| `redactr_db`       | `/data/db`     | SQLite database (`redactr-server.db`)     |
| `redactr_keys`     | `/data/keys`   | Server signing key (and cosign key)       |
| `redactr_backups`  | `/data/backups`| Nightly SQLite backups (`redactr-*.db`)   |

The `redactr_keys` volume is critical — losing the signing key invalidates all
enrolled devices. Back it up out-of-band.

## Backup and restore

The server runs a maintenance loop every 24h that writes a timestamped SQLite
backup into the backups volume as `redactr-YYYYMMDD-HHMMSS.db` and prunes all
but the newest `REDACTR_BACKUP_RETAIN` files (default 14). It also deletes
audit/event rows older than `REDACTR_AUDIT_RETAIN_DAYS` (default 365).

To **list** available backups:

```sh
docker compose exec redactr-server ls -la /data/backups
```

(or inspect the `redactr_backups` volume directly on the host).

To **restore** from a chosen backup:

```sh
# 1. Stop the server so nothing writes the DB mid-copy.
docker compose stop redactr-server

# 2. Copy the chosen backup over the live DB path (REDACTR_SERVER_DB).
#    Run a throwaway container with both volumes mounted:
docker run --rm \
  -v redactr_db:/data/db \
  -v redactr_backups:/data/backups \
  busybox \
  cp /data/backups/redactr-YYYYMMDD-HHMMSS.db /data/db/redactr-server.db

# 3. Start the server again.
docker compose start redactr-server
```

Adjust the volume names if you changed the compose project name (Docker
prefixes volumes with the project directory name).

## Using an existing nginx / Traefik instead of Caddy

If you already run a reverse proxy, drop the `caddy` service and point your
proxy at `redactr-server:8080` (or expose 8080 on the host and proxy to it).
Terminate TLS at your proxy and forward the standard headers:

```
proxy_set_header Host              $host;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
```

For Traefik, route the host rule to the `redactr-server` service on port 8080
with a TLS resolver of your choice. Keep `REDACTR_PUBLIC_URL` set to your real
external `https://` URL so cookies (Secure) and OIDC redirects are correct.

## Image checksums and signing

After building, you can pin the image by digest for reproducible deploys:

```sh
docker build -f deploy/Dockerfile -t redactr-server:test ..
docker inspect --format '{{index .RepoDigests 0}}' redactr-server:test
```

**Image signing is deferred to F2.** The build artifacts produced here are
currently **unsigned** — there is no cosign/notation signature on the
redactr-server image yet. Verify integrity via the registry digest in the
meantime; supply-chain signing will be added in a later subsystem.
