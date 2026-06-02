# Redactr v2 — Subsystem A3: Image Build/Sign/Registry Pipeline Design

**Status:** Design (autonomous-build mandate). Implementation plan follows.
**Date:** 2026-05-31
**Parent:** subsystem A (A3, the heaviest, built last). A1/A2/A4/A5 merged.
**Fills SEAM:** the C sandbox `// SEAM: verify image signature/digest`; the architecture's "admin uploads a Dockerfile → server builds + signs centrally → registry → clients pull + verify".

## Reality check (what's testable here vs deferred)

The real pipeline requires, on the server host, a **Docker/BuildKit daemon, `cosign`, and a container registry** — none available in this dev environment. So this subsystem follows the same split used for C's container runs: build the **Go orchestration** (with a command-runner seam) and the **storage + policy wiring**, fully unit-tested by asserting the command sequence against a fake runner; the **actual `docker build` / `cosign sign` / registry push / client signature-verify execution is deferred** to a Docker+cosign+registry-equipped server, and documented.

## Goal

An org admin uploads a Dockerfile (`FROM redactr-base`); the server builds it, signs it, pushes it to a registry at an immutable `ref@digest`, records it, and sets the org's policy `image` to that signed `ref@digest` — so every client launch (subsystem C) pulls the exact, signed image by digest.

## Components

### Server
1. **`internal/server/store`**: `images` table — `id`, `org_id`, `tag`, `ref`, `digest`, `status` (`building`/`ready`/`failed`), `created_at`. Methods `InsertImage`, `ListImages(orgID)`, `SetImageResult(id, ref, digest, status)`.
2. **`internal/server/imagebuild`**: a `Builder` over a **`commandRunner` seam** (mirrors `internal/sandbox`'s pattern). `Build(ctx, BuildSpec{Dockerfile, BaseRef, TargetRef}) (Result{Ref, Digest}, error)` runs, in order:
   - validate the Dockerfile starts `FROM <BaseRef>` (reject otherwise — admins may only extend the hardened base);
   - write the Dockerfile to a temp build context;
   - `docker build -t <TargetRef> -f <dockerfile> <ctx>`;
   - `docker push <TargetRef>` (capture the pushed `sha256:` digest);
   - `cosign sign --key <serverKey> <TargetRef>@<digest>`.
   Real execution shells out; tests inject a fake runner and assert the exact argv sequence + the `FROM` validation. The production runner is wired only when Docker/cosign exist (a `// DEFERRED:` note; absent tooling → a clear "image build requires docker+cosign on the server host" error).
3. **HTTP**: `POST /admin/orgs/{id}/images {dockerfile, tag}` (admin) → `InsertImage(status=building)` → `Builder.Build` → on success `SetImageResult(ready)` + `PutPolicy` with `image = ref@digest`; on failure `SetImageResult(failed)`. `GET /admin/orgs/{id}/images` (admin) lists. The `Server` gets an injectable `Builder` interface so the endpoint is testable with a fake builder (no Docker).

### Client (subsystem C integration)
4. **Digest pinning** is already enforced for free: when the policy `image` is a `registry/...@sha256:...` ref, `docker run` pulls that exact content-addressed image — the digest is the integrity guarantee. The C sandbox needs no change to honor it (it already launches `s.Image`). **cosign signature verification before run** (a stronger guarantee than digest pinning) is the **deferred** piece — documented in the C `// SEAM` as "verify with `cosign verify --key <serverPubKey>` when cosign is available on the client".

### Dashboard (A5 integration)
5. An **Images tab** in the admin dashboard: list images (tag, ref@digest, status), and an "upload Dockerfile" form (textarea + tag) → `POST .../images`. (Small JS addition to the existing dashboard.)

## Data flow

```
admin ──POST /admin/orgs/{id}/images {dockerfile,tag}──▶ server
  InsertImage(building) → imagebuild.Build (docker build → push@digest → cosign sign)
  → SetImageResult(ready, ref@digest) → PutPolicy(image=ref@digest)
client (C) ──docker run <ref@digest>──▶ content-addressed pull (digest = integrity)
        [DEFERRED] cosign verify --key <serverPubKey> before run
```

## Error handling

| Case | Behavior |
|---|---|
| Dockerfile not `FROM <BaseRef>` | 400 "must extend redactr-base" (admins can't run arbitrary base images) |
| docker/cosign not installed on server | build returns a clear "requires docker+cosign on the server host" error; image status=failed |
| build/push/sign fails | status=failed, error surfaced to the admin; policy unchanged |
| Concurrent uploads | each is its own image row; serialized store writes (SetMaxOpenConns(1)) |

## Testing

- **Store:** `InsertImage`/`ListImages`/`SetImageResult` round-trip + status transition.
- **imagebuild:** with a fake `commandRunner`, `Build` runs the exact sequence (build → push → sign) and returns the captured digest; `FROM`-validation rejects a non-base Dockerfile; missing-tooling path returns the clear error.
- **HTTP:** `POST .../images` with an **injected fake builder** records the image, transitions to ready, and updates the policy image to the returned ref@digest; `GET .../images` lists; bad Dockerfile → 400; admin-gated.
- **Deferred (documented):** real `docker build`/`cosign sign`/registry push + client `cosign verify` on a Docker+cosign+registry host.

## Build order (A3 tasks)

1. `internal/server/store`: `images` table + Insert/List/SetImageResult.
2. `internal/server/imagebuild`: `Builder` + `commandRunner` seam + `FROM` validation + argv sequence (fake-runner tested).
3. Server HTTP: `POST/GET /admin/orgs/{id}/images` with injectable `Builder` + policy wiring (fake-builder tested).
4. Dashboard Images tab (small JS).

## Out of scope / SEAMs

- Async build queue / build status polling UI (v2 builds synchronously in the request; a job queue is future work — noted).
- Client-side `cosign verify` execution (deferred; digest pinning via `docker run <ref@digest>` is the v2 integrity floor).
- Registry auth/credential management (operator configures the daemon's registry creds; out of scope here).
- BuildKit cache / multi-arch (YAGNI for v2).
