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
