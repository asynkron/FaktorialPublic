package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const workerBuildAccess = "worker-build"

var projectIDPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

type projectSourceRequest struct {
	Repo    string `json:"repo"`
	Project string `json:"project"`
}

func parseProjectAudience(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host != "app.faktorial.ai" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("project must be a canonical Faktorial Cloud project URL")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "projects" || !projectIDPattern.MatchString(parts[1]) {
		return "", errors.New("project must be a canonical Faktorial Cloud project URL")
	}
	return "https://app.faktorial.ai/projects/" + parts[1], nil
}

func (s *server) handleAPIProjectSource(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := s.setupConfigured(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "github app is not configured"})
		return
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return
	}
	user, err := s.lookupSessionUser(r.Context(), token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid session"})
		return
	}
	owner, name, project, err := decodeProjectSourceRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	authorized, err := s.canIssueRepositoryToken(r.Context(), user.ID, owner, name, workerBuildAccess)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not authorize repository"})
		return
	}
	if !authorized {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "repository is not authorized for this session"})
		return
	}
	credential, err := s.issueProjectSourceCredential(r.Context(), user.ID, owner, name, project)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create project source credential"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"repo": owner + "/" + name, "project": project, "token": credential})
}

func (s *server) handleAPIProjectSourceToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := s.setupConfigured(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "github app is not configured"})
		return
	}
	credential, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return
	}
	owner, name, project, err := decodeProjectSourceRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	userID, bound, err := s.projectSourceUser(r.Context(), credential, owner, name, project)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not authorize project source credential"})
		return
	}
	if !bound {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "project source credential is not authorized for this repository"})
		return
	}
	authorized, err := s.canIssueRepositoryToken(r.Context(), userID, owner, name, workerBuildAccess)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not authorize repository"})
		return
	}
	if !authorized {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "repository authorization has been revoked"})
		return
	}
	installation, err := s.fetchRepoInstallation(r.Context(), owner, name)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "github app is not installed for this repository", "install_url": githubAppInstallURL})
		return
	}
	accessToken, err := s.mintInstallationTokenWithAccess(r.Context(), installation.ID, name, workerBuildAccess)
	if err != nil {
		writeJSON(w, http.StatusFailedDependency, map[string]string{"error": "could not mint github token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"repo": owner + "/" + name, "project": project, "access": workerBuildAccess, "token": accessToken.Token, "expires_at": accessToken.ExpiresAt, "permissions": accessToken.Permissions})
}

func decodeProjectSourceRequest(r *http.Request) (string, string, string, error) {
	var req projectSourceRequest
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return "", "", "", errors.New("invalid json")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.Decode(new(any)) != io.EOF {
		return "", "", "", errors.New("invalid json")
	}
	owner, name, err := parseRepo(req.Repo)
	if err != nil {
		return "", "", "", errors.New("repo must be owner/name")
	}
	project, err := parseProjectAudience(req.Project)
	if err != nil {
		return "", "", "", err
	}
	return owner, name, project, nil
}

func (s *server) issueProjectSourceCredential(ctx context.Context, githubUserID int64, owner, name, project string) (string, error) {
	if s.projectSourceCredentialIssued != nil {
		return s.projectSourceCredentialIssued(ctx, githubUserID, owner, name, project)
	}
	if s.cfg == nil || s.cfg.DatabaseURL == "" {
		return "", errors.New("project source credential store is unavailable")
	}
	credential, err := randomToken(32)
	if err != nil {
		return "", err
	}
	db, err := pgxpool.New(ctx, s.cfg.DatabaseURL)
	if err != nil {
		return "", err
	}
	defer db.Close()
	tx, err := db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE faktorial_project_source_credentials SET revoked_at = now() WHERE project_audience = $1 AND revoked_at IS NULL`, project); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO faktorial_project_source_credentials(credential_hash, github_user_id, project_audience, repository_owner, repository_name, token_access) VALUES($1, $2, $3, lower($4), lower($5), $6)`, opaqueCredentialHash(credential), githubUserID, project, owner, name, workerBuildAccess); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return credential, nil
}

func (s *server) projectSourceUser(ctx context.Context, credential, owner, name, project string) (int64, bool, error) {
	if s.projectSourceCredentialUser != nil {
		return s.projectSourceCredentialUser(ctx, credential, owner, name, project)
	}
	if s.cfg == nil || s.cfg.DatabaseURL == "" {
		return 0, false, errors.New("project source credential store is unavailable")
	}
	db, err := pgxpool.New(ctx, s.cfg.DatabaseURL)
	if err != nil {
		return 0, false, err
	}
	defer db.Close()
	var userID int64
	err = db.QueryRow(ctx, `SELECT github_user_id FROM faktorial_project_source_credentials WHERE credential_hash = $1 AND project_audience = $2 AND repository_owner = lower($3) AND repository_name = lower($4) AND token_access = $5 AND revoked_at IS NULL`, opaqueCredentialHash(credential), project, owner, name, workerBuildAccess).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return userID, true, nil
}

func opaqueCredentialHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *server) verifyRepositoryWrite(ctx context.Context, oauthToken, owner, name string) (bool, error) {
	if s.repositoryWriteAuthorized != nil {
		return s.repositoryWriteAuthorized(ctx, oauthToken, owner, name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/%s", githubAPI, url.PathEscape(owner), url.PathEscape(name)), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+oauthToken)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	var body struct {
		FullName    string `json:"full_name"`
		Permissions struct {
			Push bool `json:"push"`
		} `json:"permissions"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return false, err
	}
	return strings.EqualFold(body.FullName, owner+"/"+name) && body.Permissions.Push, nil
}
