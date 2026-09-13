# Faktorial Public

Public Faktorial website plus the hosted GitHub App installation endpoint.

## Routes

- `GET /` serves the public Faktorial page.
- `GET /bokabra` serves the BokaBra case page; `GET /bokabra.html` redirects there.
- `GET /asynkron-jsengine` and `GET /jsengine` serve the Asynkron.JsEngine case page; the `.html` aliases redirect there.
- `GET /comparison` serves the product comparison sheet; `GET /product-sheet` is an alias, and the `.html` aliases redirect there.
- `GET /healthz` returns `200 OK`.
- `GET /login?callback=http://127.0.0.1:<port>/callback` starts CLI GitHub login.
- `GET /api/me` returns the logged-in GitHub user for a Faktorial bearer token.
- `POST /api/github/token` exchanges a Faktorial bearer token and `{ "repo": "owner/name" }` for a short-lived GitHub installation token.
- `GET /setup?installation_id=...&setup_action=install` verifies the GitHub App installation and stores it in Supabase/Postgres.
- `GET /github/setup?installation_id=...&setup_action=install` is kept as a compatibility alias.
- `GET /callback` completes GitHub OAuth login and redirects back to the CLI callback.

## GitHub App Settings

For the hosted SaaS app:

- Set **Where can this GitHub App be installed?** to `Any account`.
- Set **Setup URL** to `https://<your-domain>/setup`.
- Leave **Request user authorization (OAuth) during installation** off unless the SaaS needs to link the installing GitHub user.
- Leave **Callback URL** empty unless OAuth is enabled.

## Environment

Required:

```bash
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..."
GITHUB_OAUTH_CLIENT_ID=Ov23li...
GITHUB_OAUTH_CLIENT_SECRET=...
DATABASE_URL="postgresql://postgres:...@...supabase.co:5432/postgres"
```

Optional:

```bash
PORT=8080
PUBLIC_BASE_URL=https://faktorial.ai
```

`GITHUB_APP_PRIVATE_KEY` can contain literal newlines or escaped `\n` sequences.

The GitHub App callback URL must include `https://faktorial.ai/callback` for
CLI login to work.

## Database

Apply the versioned files in `supabase/migrations` before deploying. `schema.sql`
is retained for the original GitHub App installation table bootstrap.

## Local Run

```bash
go run .
```

## Docker

```bash
docker build -t faktorial-public .
docker run --rm -p 8080:8080 --env-file .env faktorial-public
```

To publish the production image:

```bash
./build.sh
./build.sh 2026-04-26
```

The script publishes `rogeralsing/faktorialpublic:<tag>`. When the tag is not
`latest`, it also updates `rogeralsing/faktorialpublic:latest`.

## Read-only repository tokens

Authorized callers may send `{ "repo": "owner/name", "access": "contents-read" }`
to the existing `/api/github/token` endpoint. The broker requests exactly that
repository and `contents: read`, then checks GitHub's returned permissions before
returning the token. Only implicit `metadata: read` is also accepted. The response
includes `access`, `permissions`, `token` and `expires_at` and is marked no-store.
An omitted access field preserves the existing CLI token permission behavior.
Unknown access modes fail instead of falling back to broader permissions.

Before contacting GitHub, the broker requires an exact
`faktorial_repository_grants` row for the authenticated GitHub user, repository,
and requested access mode. An omitted access field maps to the explicit `legacy`
grant. Missing grants fail closed with `403 Forbidden`. Project pods must not
receive the Faktorial session or the app private key. Tokens still expire and
callers must renew before using them for a subsequent fetch. This change does not
implement Kubernetes rotation.

### Project worker Build tokens

`POST /api/github/token` also accepts `access: "worker-build"`. It requires an
explicit `faktorial_repository_grants` row for that exact access mode, GitHub user
and repository. Contents-read and legacy grants do not authorize this mode.
Apply migration `20260909214500_worker_build_repository_grants.sql` before enrolling
worker-build grants; the migration itself grants nothing.

The token request names one repository and exactly `contents: read`,
`pull_requests: write` and `issues: write`. The broker verifies those permissions
in GitHub's response, allowing only the implicit `metadata: read` addition. This
mode supports reading worker commits and writing PRs/comments. It does not grant
code-write or repository administration access. Existing empty-access and
contents-read requests retain their behavior.

Validation: the Go race suite tests single-repository requests, exact permission
confirmation, rejection of extra/missing rights and denial before any GitHub call
when the session lacks a worker-build grant. The constraint migration was tested
in a rolled-back local PostgreSQL transaction, preserving prior modes and rejecting
an unknown mode. Production migration, grants and broker deployment are separate
rollout steps and were not performed with this change.

### Project source delegation

A worker can turn its existing Faktorial session into one renewable, project-bound
source credential without sending that session to the project:

1. `POST /api/github/project-source` with the Faktorial session bearer and
   `{ "repo": "owner/name", "project": "https://app.faktorial.ai/projects/<id>" }`
   returns `{ "repo", "project", "token" }`. The response token is opaque; only
   its hash is stored. It is bound to that exact repository, Cloud project and
   `worker-build` access mode.
2. `POST /api/github/project-source/token` with that opaque bearer and the same
   JSON returns `{ "repo", "project", "access": "worker-build", "token",
   "expires_at", "permissions" }`. It rechecks the exact repository grant on
   every renewal and mints one short-lived installation token for one repository.

Project URLs must be canonical `https://app.faktorial.ai/projects/<id>` values.
A token for another project or repository is rejected. The service never returns
Faktorial login sessions or the GitHub App private key.

When an agent needs a missing worker-build grant, it starts the existing GitHub
App user-login flow with `repo=owner/name&access=worker-build`. The OAuth token is
used only during that callback to verify GitHub reports exact repository `push`
access, then discarded. A successful check records the exact grant; ordinary
login requests do not create grants. The broker does not request broad `repo`
OAuth scope or infer access from repository visibility. If GitHub cannot prove
push access, the user must complete the explicit repository login after granting
the Faktorial GitHub App access.

Worker-build tokens request and verify only `contents: write`, `pull_requests:
write`, `issues: write`, `checks: read` and `statuses: read` (plus GitHub's
implicit metadata permission). Apply
`20260913153000_project_source_credentials.sql` before enabling these routes.
