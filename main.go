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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const githubAPI = "https://api.github.com"

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db pool: %v", err)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		log.Fatalf("db ping: %v", err)
	}

	app := &server{
		cfg: cfg,
		db:  db,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/healthz", app.handleHealthz)
	mux.HandleFunc("/github/setup", app.handleGitHubSetup)
	mux.HandleFunc("/bokabra.html", app.handleStaticFile)
	mux.HandleFunc("/pitch.html", app.handleStaticFile)
	mux.HandleFunc("/header.css", app.handleStaticFile)
	mux.HandleFunc("/header.js", app.handleStaticFile)
	mux.HandleFunc("/faktorialai.png", app.handleStaticFile)
	mux.HandleFunc("/faktorialai-plain.png", app.handleStaticFile)
	mux.Handle("/logos/", http.StripPrefix("/logos/", http.FileServer(http.Dir("logos"))))
	mux.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("images"))))

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("faktorial public app listening on :%s", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http server: %v", err)
	}
}

type config struct {
	Port             string
	PublicBaseURL    string
	GitHubAppID      string
	GitHubPrivateKey *rsa.PrivateKey
	DatabaseURL      string
}

func loadConfig() (*config, error) {
	appID := strings.TrimSpace(os.Getenv("GITHUB_APP_ID"))
	if appID == "" {
		return nil, errors.New("GITHUB_APP_ID is required")
	}
	keyPEM := strings.TrimSpace(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
	if keyPEM == "" {
		return nil, errors.New("GITHUB_APP_PRIVATE_KEY is required")
	}
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dbURL == "" {
		dbURL = strings.TrimSpace(os.Getenv("SUPABASE_DATABASE_URL"))
	}
	if dbURL == "" {
		return nil, errors.New("DATABASE_URL or SUPABASE_DATABASE_URL is required")
	}
	key, err := parsePrivateKey(strings.ReplaceAll(keyPEM, `\n`, "\n"))
	if err != nil {
		return nil, fmt.Errorf("GITHUB_APP_PRIVATE_KEY: %w", err)
	}
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	return &config{
		Port:             port,
		PublicBaseURL:    strings.TrimRight(os.Getenv("PUBLIC_BASE_URL"), "/"),
		GitHubAppID:      appID,
		GitHubPrivateKey: key,
		DatabaseURL:      dbURL,
	}, nil
}

type server struct {
	cfg        *config
	db         *pgxpool.Pool
	httpClient *http.Client
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "index.html")
}

func (s *server) handleStaticFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" || strings.Contains(name, "..") || filepath.Base(name) != name {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, name)
}

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

func (s *server) handleGitHubSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

func (s *server) storeInstallation(ctx context.Context, installation *githubInstallation, setupAction string) error {
	permissions, err := json.Marshal(installation.Permissions)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `
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
  <title>Faktorial connected</title>
  <style>
    body { margin: 0; font: 16px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #17202a; background: #f7f9fb; }
    main { max-width: 520px; margin: 12vh auto; padding: 32px; background: #fff; border: 1px solid #dde5ee; border-radius: 8px; }
    h1 { margin: 0 0 12px; font-size: 28px; line-height: 1.15; }
    p { margin: 0 0 16px; }
    dl { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; margin: 20px 0 0; }
    dt { color: #607086; }
    dd { margin: 0; font-weight: 600; }
  </style>
</head>
<body>
  <main>
    <h1>GitHub connected</h1>
    <p>Faktorial can now access the selected repositories for {{.AccountLogin}}.</p>
    <dl>
      <dt>Account</dt><dd>{{.AccountLogin}} ({{.AccountType}})</dd>
      <dt>Installation ID</dt><dd>{{.InstallationID}}</dd>
    </dl>
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
