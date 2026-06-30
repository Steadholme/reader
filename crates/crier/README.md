# Crier

**Single-user ActivityPub microblog — sovereign fediverse identity for the HOLDFAST estate.**

Crier lets you own your social identity on the open social web: a local microblog (post + read
notes) backed by a real ActivityPub actor, WebFinger discovery, and an outbox that any fediverse
server (Mastodon, etc.) can follow. Inbound `Follow` / `Undo` / `Create` are accepted best-effort.

## Surfaces (split at the Sluice gateway)

| Path | Gateway auth | Purpose |
|------|--------------|---------|
| `GET /` | `sso` | The timeline + composer (gateway-injected `X-Auth-*`). |
| `POST /api/notes` | `sso` + CSRF | Create a note. |
| `GET /.well-known/webfinger` | **public** | Resolve `acct:<actor>@<domain>` to the actor. |
| `GET /users/{name}` | **public** | The ActivityPub Actor (Person) document. |
| `GET /users/{name}/outbox`, `GET /outbox` | **public** | OrderedCollection of public notes. |
| `GET /users/{name}/followers` | **public** | Followers collection. |
| `GET /users/{name}/notes/{id}` | **public** | A dereferenceable Note object. |
| `POST /users/{name}/inbox`, `POST /inbox` | **public** | Accept Follow / Undo / Create (best-effort). |
| `GET /healthz` | public | Liveness (container HEALTHCHECK). |

Longer/explicit prefixes win at the gateway, so the public ActivityPub paths override the `/`=sso
default (the cellar `/v2/` precedent).

## Federation: best-effort, UNSIGNED (degraded by design)

Crier serves a **fully correct** actor / outbox / WebFinger and accepts inbound activities. Outbound
delivery (Accept on Follow, Create fan-out) uses `reqwest` + **rustls** and is **unsigned**: Crier
deliberately implements NO HTTP Signatures, because a signing stack risks pulling OpenSSL, which the
HOLDFAST posture forbids. Consequences:

- The actor document advertises **no `publicKey`**.
- Remote servers that require signed delivery will reject Crier's pushes. That is acceptable
  degradation — the **local microblog + actor/outbox JSON are correct regardless** of whether any
  remote ever talks to Crier, and inbound Follows are recorded either way.

Delivery is fire-and-forget (spawned tasks with bounded timeouts), so a slow/unreachable remote
**never blocks a request**.

## Configuration

Boots zero-config (in-memory store, federation on, audit off).

| Env | Default | Meaning |
|-----|---------|---------|
| `BIND_ADDR` | `0.0.0.0:9190` | Listen address. |
| `CRIER_ACTOR` | `w33d` | The single user's handle / `preferredUsername`. |
| `CRIER_DOMAIN` | `social.w33d.xyz` | Federation domain (actor ids resolve under `https://<domain>`). |
| `CRIER_DISPLAY_NAME` | `<actor>` | Display name. |
| `CRIER_SUMMARY` | (estate blurb) | Profile bio. |
| `CRIER_FEDERATE` | `true` | Attempt best-effort outbound delivery. |
| `CRIER_STORE` | `memory` | `memory` or `postgres`. |
| `DATABASE_URL` | — | Required when `CRIER_STORE=postgres`. |
| `AUDIT_ENABLED` | off | Enable the non-blocking Watchtower audit emitter. |
| `WATCHTOWER_URL` | — | e.g. `http://watchtower:8500`. |
| `AUDIT_INGEST_TOKEN` | — | Bearer token for Watchtower ingest. |

## Storage (portable standard SQL)

`notes(id PK, author_sub, content, visibility DEFAULT 'public', created_at)` + `INDEX(created_at)`;
`followers(actor PK, inbox_url DEFAULT '', created_at)`. Runtime sqlx queries only (no macros, no
database needed to build); rustls TLS; the same statements run unchanged on FusionDB over pgwire.

## Audit

Notable events go to Watchtower via the shared non-blocking bounded-queue emitter (`source=crier`):
`crier.note.create`, `crier.follower.add`, `crier.follower.remove`. Watchtower being down never
blocks a request.

## Build & test

```sh
CARGO_BUILD_JOBS=2 cargo check --all-targets
cargo test            # in-memory, database-free
```
