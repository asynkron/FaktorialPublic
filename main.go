package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var githubAPI = "https://api.github.com"

const githubAppInstallURL = "https://github.com/apps/faktorial-ai/installations/new"

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	app := &server{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("faktorial public app listening on :%s", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http server: %v", err)
	}
}

type config struct {
	Port              string
	PublicBaseURL     string
	GitHubAppID       string
	GitHubPrivateKey  *rsa.PrivateKey
	GitHubKeyError    error
	GitHubOAuthID     string
	GitHubOAuthSecret string
	DatabaseURL       string
}

func loadConfig() (*config, error) {
	appID := strings.TrimSpace(os.Getenv("GITHUB_APP_ID"))
	keyPEM := strings.TrimSpace(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dbURL == "" {
		dbURL = strings.TrimSpace(os.Getenv("SUPABASE_DATABASE_URL"))
	}
	var key *rsa.PrivateKey
	var keyErr error
	if keyPEM != "" {
		key, keyErr = parsePrivateKey(strings.ReplaceAll(keyPEM, `\n`, "\n"))
	}
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	return &config{
		Port:              port,
		PublicBaseURL:     strings.TrimRight(os.Getenv("PUBLIC_BASE_URL"), "/"),
		GitHubAppID:       appID,
		GitHubPrivateKey:  key,
		GitHubKeyError:    keyErr,
		GitHubOAuthID:     strings.TrimSpace(os.Getenv("GITHUB_OAUTH_CLIENT_ID")),
		GitHubOAuthSecret: strings.TrimSpace(os.Getenv("GITHUB_OAUTH_CLIENT_SECRET")),
		DatabaseURL:       dbURL,
	}, nil
}

type server struct {
	cfg        *config
	httpClient *http.Client
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/api/me", s.handleAPIIdentity)
	mux.HandleFunc("/api/github/token", s.handleAPIGitHubToken)
	mux.HandleFunc("/setup", s.handleGitHubSetup)
	mux.HandleFunc("/github/setup", s.handleGitHubSetup)
	mux.HandleFunc("/callback", s.handleGitHubCallback)
	mux.HandleFunc("/bokabra", s.handleCasePage)
	mux.HandleFunc("/bokabra.html", s.handleBokabraRedirect)
	mux.HandleFunc("/case.html", s.handleCasePage)
	mux.HandleFunc("/asynkron-jsengine", s.handleJsEngineCasePage)
	mux.HandleFunc("/jsengine", s.handleJsEngineCasePage)
	mux.HandleFunc("/asynkron-jsengine.html", s.handleJsEngineRedirect)
	mux.HandleFunc("/jsengine.html", s.handleJsEngineRedirect)
	mux.Handle("/", http.FileServer(http.Dir("static")))
	return mux
}

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

func (s *server) handleBokabraRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := "/bokabra"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func (s *server) handleCasePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "static/bokabra.html")
}

func (s *server) handleJsEngineRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := "/asynkron-jsengine"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func (s *server) handleJsEngineCasePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "static/asynkron-jsengine.html")
}

func (s *server) handleGitHubSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.setupConfigured(); err != nil {
		log.Printf("github setup config missing: %v", err)
		renderSetupError(w, http.StatusOK, "Faktorial GitHub setup is not configured yet.")
		return
	}

	installationID, err := parsePositiveInt64(r.URL.Query().Get("installation_id"))
	if err != nil {
		renderSetupError(w, http.StatusBadRequest, "Missing or invalid installation_id.")
		return
	}
	setupAction := strings.TrimSpace(r.URL.Query().Get("setup_action"))
	if setupAction == "" {
		setupAction = "install"
	}

	installation, err := s.fetchInstallation(r.Context(), installationID)
	if err != nil {
		log.Printf("github setup verify failed: installation_id=%d error=%v", installationID, err)
		renderSetupError(w, http.StatusBadGateway, "Could not verify the GitHub App installation yet.")
		return
	}
	if err := s.storeInstallation(r.Context(), installation, setupAction); err != nil {
		log.Printf("github setup store failed: installation_id=%d error=%v", installationID, err)
		renderSetupError(w, http.StatusInternalServerError, "GitHub connected, but Faktorial could not save the installation.")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = setupSuccessTemplate.Execute(w, map[string]any{
		"AccountLogin":   installation.Account.Login,
		"AccountType":    installation.Account.Type,
		"InstallationID": installation.ID,
		"PublicBaseURL":  s.cfg.PublicBaseURL,
	})
}

func (s *server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		renderSetupError(w, http.StatusOK, "Faktorial user authorization is not enabled for this GitHub App.")
		return
	}
	if err := s.authConfigured(); err != nil {
		log.Printf("github oauth callback config missing: %v", err)
		renderSetupError(w, http.StatusOK, "Faktorial login is not configured yet.")
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	loginState, err := s.consumeLoginState(r.Context(), state)
	if err != nil {
		log.Printf("github oauth state invalid: %v", err)
		renderSetupError(w, http.StatusBadRequest, "Login expired. Run faktorial login again.")
		return
	}
	accessToken, err := s.exchangeGitHubOAuthCode(r.Context(), code)
	if err != nil {
		log.Printf("github oauth exchange failed: %v", err)
		renderSetupError(w, http.StatusBadGateway, "GitHub login failed.")
		return
	}
	user, err := s.fetchGitHubUser(r.Context(), accessToken)
	if err != nil {
		log.Printf("github oauth user lookup failed: %v", err)
		renderSetupError(w, http.StatusBadGateway, "Could not read your GitHub identity.")
		return
	}
	sessionToken, err := randomToken(32)
	if err != nil {
		log.Printf("session token generation failed: %v", err)
		renderSetupError(w, http.StatusInternalServerError, "Could not create a Faktorial session.")
		return
	}
	if err := s.storeSession(r.Context(), user, sessionToken); err != nil {
		log.Printf("session store failed: %v", err)
		renderSetupError(w, http.StatusInternalServerError, "Could not save your Faktorial session.")
		return
	}
	redirectURL, err := url.Parse(loginState.LocalCallbackURL)
	if err != nil {
		log.Printf("stored callback url invalid: %v", err)
		renderSetupError(w, http.StatusInternalServerError, "Stored login callback is invalid.")
		return
	}
	q := redirectURL.Query()
	q.Set("state", loginState.CLIState)
	q.Set("token", sessionToken)
	q.Set("login", user.Login)
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (s *server) fetchInstallation(ctx context.Context, installationID int64) (*githubInstallation, error) {
	jwt, err := signAppJWT(s.cfg.GitHubAppID, s.cfg.GitHubPrivateKey)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/app/installations/%d", githubAPI, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github installation lookup status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var installation githubInstallation
	if err := json.Unmarshal(body, &installation); err != nil {
		return nil, err
	}
	if installation.ID != installationID {
		return nil, fmt.Errorf("github returned installation_id=%d, want %d", installation.ID, installationID)
	}
	return &installation, nil
}

func (s *server) fetchRepoInstallation(ctx context.Context, owner, repo string) (*githubInstallation, error) {
	jwt, err := signAppJWT(s.cfg.GitHubAppID, s.cfg.GitHubPrivateKey)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/repos/%s/%s/installation", githubAPI, url.PathEscape(owner), url.PathEscape(repo))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github repo installation lookup status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var installation githubInstallation
	if err := json.Unmarshal(body, &installation); err != nil {
		return nil, err
	}
	if installation.ID == 0 {
		return nil, errors.New("github repo installation response missing id")
	}
	return &installation, nil
}

type installationAccessToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *server) mintInstallationAccessToken(ctx context.Context, installationID int64, repo string) (*installationAccessToken, error) {
	jwt, err := signAppJWT(s.cfg.GitHubAppID, s.cfg.GitHubPrivateKey)
	if err != nil {
		return nil, err
	}
	payload := map[string][]string{"repositories": []string{repo}}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", githubAPI, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github installation token status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out installationAccessToken
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if out.Token == "" {
		return nil, errors.New("github installation token response missing token")
	}
	if out.ExpiresAt.IsZero() {
		return nil, errors.New("github installation token response missing expires_at")
	}
	return &out, nil
}

func (s *server) storeInstallation(ctx context.Context, installation *githubInstallation, setupAction string) error {
	db, err := pgxpool.New(ctx, s.cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("db pool: %w", err)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		return fmt.Errorf("db ping: %w", err)
	}
	permissions, err := json.Marshal(installation.Permissions)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `
insert into github_app_installations (
    installation_id,
    account_id,
    account_login,
    account_type,
    html_url,
    target_type,
    permissions,
    repository_selection,
    setup_action,
    suspended_at,
    updated_at
) values ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, now())
on conflict (installation_id) do update set
    account_id = excluded.account_id,
    account_login = excluded.account_login,
    account_type = excluded.account_type,
    html_url = excluded.html_url,
    target_type = excluded.target_type,
    permissions = excluded.permissions,
    repository_selection = excluded.repository_selection,
    setup_action = excluded.setup_action,
    suspended_at = excluded.suspended_at,
    updated_at = now()
`, installation.ID,
		installation.Account.ID,
		installation.Account.Login,
		installation.Account.Type,
		installation.HTMLURL,
		installation.TargetType,
		string(permissions),
		installation.RepositorySelection,
		setupAction,
		installation.SuspendedAt,
	)
	return err
}

func (s *server) setupConfigured() error {
	var missing []string
	if strings.TrimSpace(s.cfg.GitHubAppID) == "" {
		missing = append(missing, "GITHUB_APP_ID")
	}
	if s.cfg.GitHubPrivateKey == nil {
		missing = append(missing, "GITHUB_APP_PRIVATE_KEY")
	}
	if strings.TrimSpace(s.cfg.DatabaseURL) == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	if s.cfg.GitHubKeyError != nil {
		return fmt.Errorf("GITHUB_APP_PRIVATE_KEY: %w", s.cfg.GitHubKeyError)
	}
	return nil
}

type githubInstallation struct {
	ID                  int64             `json:"id"`
	Account             githubAccount     `json:"account"`
	HTMLURL             string            `json:"html_url"`
	TargetType          string            `json:"target_type"`
	Permissions         map[string]string `json:"permissions"`
	RepositorySelection string            `json:"repository_selection"`
	SuspendedAt         *time.Time        `json:"suspended_at"`
}

type githubAccount struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

func parsePositiveInt64(raw string) (int64, error) {
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || v <= 0 {
		return 0, errors.New("expected positive integer")
	}
	return v, nil
}

func signAppJWT(appID string, key *rsa.PrivateKey) (string, error) {
	now := time.Now().Unix()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	payload := map[string]any{
		"iat": now - 60,
		"exp": now + int64((9 * time.Minute).Seconds()),
		"iss": appID,
	}
	encodedHeader, err := base64JSON(header)
	if err != nil {
		return "", err
	}
	encodedPayload, err := base64JSON(payload)
	if err != nil {
		return "", err
	}
	signingInput := encodedHeader + "." + encodedPayload
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func base64JSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("PEM decode failed")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := anyKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func renderSetupError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = setupErrorTemplate.Execute(w, map[string]string{"Message": message})
}

var setupSuccessTemplate = template.Must(template.New("setup-success").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Faktorial is connected</title>
  <style>
    :root { color-scheme: dark; --bg: #0e0e0f; --panel: #161719; --panel-2: #202326; --text: #eef4f6; --muted: #a8b7bd; --line: rgba(0, 218, 243, .24); --cyan: #00daf3; --green: #4ade80; }
    * { box-sizing: border-box; }
    body { min-width: 320px; margin: 0; font: 16px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--text); background: radial-gradient(circle at 50% 0%, rgba(0, 218, 243, .12), transparent 34%), linear-gradient(180deg, #090a0b 0%, var(--bg) 100%); }
    main { width: min(960px, calc(100% - 40px)); margin: 9vh auto; }
    .eyebrow { display: inline-flex; align-items: center; gap: 10px; margin-bottom: 18px; color: var(--green); font-size: 13px; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
    .dot { width: 10px; height: 10px; background: var(--green); box-shadow: 0 0 22px rgba(74, 222, 128, .55); }
    h1 { max-width: 760px; margin: 0 0 14px; font-size: clamp(38px, 7vw, 76px); line-height: .96; letter-spacing: 0; }
    .lead { max-width: 680px; margin: 0 0 34px; color: var(--muted); font-size: 19px; }
    .grid { display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(280px, .95fr); gap: 18px; align-items: start; }
    section, aside { border: 1px solid var(--line); background: rgba(22, 23, 25, .82); box-shadow: 0 22px 70px rgba(0, 0, 0, .34); }
    section { padding: 26px; }
    aside { padding: 24px; }
    h2 { margin: 0 0 18px; font-size: 18px; letter-spacing: 0; }
    ol { display: grid; gap: 16px; margin: 0; padding: 0; list-style: none; counter-reset: step; }
    li { display: grid; grid-template-columns: 34px minmax(0, 1fr); gap: 14px; align-items: start; counter-increment: step; }
    li::before { content: counter(step); display: grid; place-items: center; width: 34px; height: 34px; border: 1px solid var(--line); color: var(--cyan); font-weight: 900; }
    h3 { margin: 1px 0 8px; font-size: 16px; }
    p { margin: 0; color: var(--muted); }
    code, pre { font: 14px/1.45 "SFMono-Regular", Consolas, ui-monospace, monospace; }
    pre { overflow-x: auto; margin: 10px 0 0; padding: 14px; border: 1px solid rgba(255,255,255,.08); background: #090a0b; color: #d9fbff; }
    dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 10px 16px; margin: 0; }
    dt { color: var(--muted); }
    dd { min-width: 0; margin: 0; font-weight: 700; overflow-wrap: anywhere; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 22px; }
    a { color: inherit; }
    .button { display: inline-flex; min-height: 42px; align-items: center; justify-content: center; border: 1px solid var(--line); padding: 0 15px; color: var(--text); font-weight: 800; text-decoration: none; }
    .button.primary { border-color: rgba(0, 218, 243, .76); background: var(--cyan); color: #001f24; }
    .note { margin-top: 22px; padding-top: 18px; border-top: 1px solid rgba(255,255,255,.08); color: var(--muted); font-size: 14px; }
    @media (max-width: 760px) {
      main { width: min(100% - 28px, 960px); margin: 40px auto; }
      .grid { grid-template-columns: 1fr; }
      h1 { font-size: clamp(36px, 12vw, 54px); }
      section, aside { padding: 20px; }
      dl { grid-template-columns: 1fr; gap: 2px 0; }
      dd { margin-bottom: 10px; }
    }
  </style>
</head>
<body>
  <main>
    <div class="eyebrow"><span class="dot"></span> GitHub App installed</div>
    <h1>Faktorial is connected.</h1>
    <p class="lead">Faktorial can now access the selected repositories for {{.AccountLogin}}. Install the CLI, sign in, then run it inside a GitHub repository.</p>
    <div class="grid">
      <section>
        <h2>Use Faktorial from your terminal</h2>
        <ol>
          <li>
            <div>
              <h3>Install the CLI</h3>
              <p>Use npm if you want the packaged installer.</p>
              <pre><code>npm install -g @asynkron/faktorial</code></pre>
            </div>
          </li>
          <li>
            <div>
              <h3>Sign in</h3>
              <p>This connects your terminal to your GitHub identity.</p>
              <pre><code>faktorial login</code></pre>
            </div>
          </li>
          <li>
            <div>
              <h3>Run it in a repo</h3>
              <p>Open a repository where the GitHub App is installed.</p>
              <pre><code>cd path/to/your/repo
faktorial</code></pre>
            </div>
          </li>
        </ol>
      </section>
      <aside>
        <h2>Connected account</h2>
        <dl>
          <dt>Account</dt><dd>{{.AccountLogin}}</dd>
          <dt>Type</dt><dd>{{.AccountType}}</dd>
          <dt>Installation</dt><dd>{{.InstallationID}}</dd>
        </dl>
        <div class="actions">
          <a class="button primary" href="https://www.npmjs.com/package/@asynkron/faktorial">npm package</a>
          <a class="button" href="https://github.com/apps/faktorial-ai/installations/new">Manage install</a>
        </div>
        <p class="note">Access is limited to the repositories selected during GitHub App installation. You can change that later from GitHub.</p>
      </aside>
    </div>
  </main>
</body>
</html>`))

var setupErrorTemplate = template.Must(template.New("setup-error").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Faktorial setup failed</title>
  <style>
    body { margin: 0; font: 16px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #17202a; background: #f7f9fb; }
    main { max-width: 520px; margin: 12vh auto; padding: 32px; background: #fff; border: 1px solid #dde5ee; border-radius: 8px; }
    h1 { margin: 0 0 12px; font-size: 28px; line-height: 1.15; }
    p { margin: 0; }
  </style>
</head>
<body>
  <main>
    <h1>Setup needs attention</h1>
    <p>{{.Message}}</p>
  </main>
</body>
</html>`))
