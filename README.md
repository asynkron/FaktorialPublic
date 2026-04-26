# Faktorial Public

Public Faktorial website plus the hosted GitHub App installation endpoint.

## Routes

- `GET /` serves the public Faktorial page.
- `GET /bokabra.html` and `GET /pitch.html` serve existing static pages.
- `GET /healthz` returns `200 OK`.
- `GET /login?callback=http://127.0.0.1:<port>/callback` starts CLI GitHub login.
- `GET /api/me` returns the logged-in GitHub user for a Faktorial bearer token.
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

Run `schema.sql` in Supabase before deploying.

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
