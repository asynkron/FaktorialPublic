package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	githubOAuthAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubOAuthTokenURL     = "https://github.com/login/oauth/access_token"
	sessionTTL              = 30 * 24 * time.Hour
	loginStateTTL           = 10 * time.Minute
)

type loginState struct {
	State            string
	CLIState         string
	LocalCallbackURL string
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.authConfigured(); err != nil {
		renderSetupError(w, http.StatusOK, "Faktorial login is not configured yet.")
		return
	}
	localCallback := strings.TrimSpace(r.URL.Query().Get("callback"))
	if err := validateLocalCallbackURL(localCallback); err != nil {
		renderSetupError(w, http.StatusBadRequest, "Invalid CLI callback URL.")
		return
	}
	cliState := strings.TrimSpace(r.URL.Query().Get("state"))
	if cliState == "" {
		renderSetupError(w, http.StatusBadRequest, "Missing CLI login state.")
		return
	}
	state, err := randomToken(24)
	if err != nil {
		renderSetupError(w, http.StatusInternalServerError, "Could not start login.")
		return
	}
	if err := s.storeLoginState(r.Context(), state, cliState, localCallback); err != nil {
		renderSetupError(w, http.StatusInternalServerError, "Could not start login.")
		return
	}
	callbackURL := s.cfg.PublicBaseURL + "/callback"
	q := url.Values{}
	q.Set("client_id", s.cfg.GitHubOAuthID)
	q.Set("redirect_uri", callbackURL)
	q.Set("state", state)
	q.Set("scope", "read:user")
	http.Redirect(w, r, githubOAuthAuthorizeURL+"?"+q.Encode(), http.StatusFound)
}

func (s *server) handleAPIIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return
	}
	user, err := s.userForSession(r.Context(), token)
	if err != nil {
		status := http.StatusUnauthorized
		if !errors.Is(err, pgx.ErrNoRows) {
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, map[string]string{"error": "invalid session"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"github_user_id": user.ID,
		"login":          user.Login,
		"name":           user.Name,
		"avatar_url":     user.AvatarURL,
		"html_url":       user.HTMLURL,
	})
}

func (s *server) authConfigured() error {
	var missing []string
	if s.cfg.PublicBaseURL == "" {
		missing = append(missing, "PUBLIC_BASE_URL")
	}
	if s.cfg.GitHubOAuthID == "" {
		missing = append(missing, "GITHUB_OAUTH_CLIENT_ID")
	}
	if s.cfg.GitHubOAuthSecret == "" {
		missing = append(missing, "GITHUB_OAUTH_CLIENT_SECRET")
	}
	if s.cfg.DatabaseURL == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateLocalCallbackURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" {
		return errors.New("callback must be http")
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return errors.New("callback must use loopback host")
	}
	if u.Port() == "" {
		return errors.New("callback must include port")
	}
	return nil
}

func (s *server) exchangeGitHubOAuthCode(ctx context.Context, code string) (string, error) {
	payload := map[string]string{
		"client_id":     s.cfg.GitHubOAuthID,
		"client_secret": s.cfg.GitHubOAuthSecret,
		"code":          code,
		"redirect_uri":  s.cfg.PublicBaseURL + "/callback",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubOAuthTokenURL, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github oauth token status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Error != "" {
		return "", fmt.Errorf("github oauth error %s: %s", out.Error, out.Description)
	}
	if out.AccessToken == "" {
		return "", errors.New("github oauth response missing access_token")
	}
	return out.AccessToken, nil
}

func (s *server) fetchGitHubUser(ctx context.Context, accessToken string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
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
		return nil, fmt.Errorf("github user status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var user githubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}
	if user.ID == 0 || user.Login == "" {
		return nil, errors.New("github user response missing id/login")
	}
	return &user, nil
}

func (s *server) storeLoginState(ctx context.Context, state, cliState, localCallbackURL string) error {
	db, err := pgxpool.New(ctx, s.cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(ctx, `
insert into faktorial_login_states (state, cli_state, local_callback_url, expires_at)
values ($1, $2, $3, now() + $4::interval)
`, state, cliState, localCallbackURL, fmt.Sprintf("%d seconds", int(loginStateTTL.Seconds())))
	return err
}

func (s *server) consumeLoginState(ctx context.Context, state string) (*loginState, error) {
	if state == "" {
		return nil, errors.New("missing state")
	}
	db, err := pgxpool.New(ctx, s.cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var out loginState
	err = tx.QueryRow(ctx, `
delete from faktorial_login_states
where state = $1 and expires_at > now()
returning state, cli_state, local_callback_url
`, state).Scan(&out.State, &out.CLIState, &out.LocalCallbackURL)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *server) storeSession(ctx context.Context, user *githubUser, token string) error {
	db, err := pgxpool.New(ctx, s.cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(ctx, `
insert into faktorial_users (github_user_id, login, name, email, avatar_url, html_url, updated_at)
values ($1, $2, $3, $4, $5, $6, now())
on conflict (github_user_id) do update set
    login = excluded.login,
    name = excluded.name,
    email = excluded.email,
    avatar_url = excluded.avatar_url,
    html_url = excluded.html_url,
    updated_at = now()
`, user.ID, user.Login, user.Name, user.Email, user.AvatarURL, user.HTMLURL)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `
insert into faktorial_sessions (token_hash, github_user_id, github_login, expires_at)
values ($1, $2, $3, now() + $4::interval)
`, sessionTokenHash(token), user.ID, user.Login, fmt.Sprintf("%d seconds", int(sessionTTL.Seconds())))
	return err
}

func (s *server) userForSession(ctx context.Context, token string) (*githubUser, error) {
	db, err := pgxpool.New(ctx, s.cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var user githubUser
	err = db.QueryRow(ctx, `
select u.github_user_id, u.login, u.name, u.email, u.avatar_url, u.html_url
from faktorial_sessions s
join faktorial_users u on u.github_user_id = s.github_user_id
where s.token_hash = $1 and s.expires_at > now()
`, sessionTokenHash(token)).Scan(&user.ID, &user.Login, &user.Name, &user.Email, &user.AvatarURL, &user.HTMLURL)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func sessionTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func bearerToken(header string) (string, bool) {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
