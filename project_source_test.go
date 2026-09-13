package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProjectSourceCredentialIssuesOnlyForExactWorkerBuildGrant(t *testing.T) {
	issued := false
	s := projectSourceTestServer(t)
	s.repositoryTokenAuthorized = func(_ context.Context, id int64, owner, repo, access string) (bool, error) {
		if id != 9 || owner != "asynkron" || repo != "Faktorial" || access != workerBuildAccess {
			t.Fatalf("grant input %d %s/%s %s", id, owner, repo, access)
		}
		return false, nil
	}
	s.projectSourceCredentialIssued = func(context.Context, int64, string, string, string) (string, error) {
		issued = true
		return "unexpected", nil
	}
	rec := postProjectSource(t, s, "/api/github/project-source", "session", "asynkron/Faktorial", "https://app.faktorial.ai/projects/inmem")
	if rec.Code != http.StatusForbidden || issued {
		t.Fatalf("status=%d issued=%v body=%s", rec.Code, issued, rec.Body.String())
	}
}

func TestProjectSourceRenewalIsBoundAndRechecksGrant(t *testing.T) {
	s := projectSourceTestServer(t)
	checks := 0
	s.projectSourceCredentialUser = func(_ context.Context, credential, owner, repo, project string) (int64, bool, error) {
		if credential != "opaque" || owner != "asynkron" || repo != "Faktorial" || project != "https://app.faktorial.ai/projects/inmem" {
			t.Fatalf("binding %q %s/%s %s", credential, owner, repo, project)
		}
		return 9, true, nil
	}
	s.repositoryTokenAuthorized = func(_ context.Context, id int64, owner, repo, access string) (bool, error) {
		checks++
		return id == 9 && owner == "asynkron" && repo == "Faktorial" && access == workerBuildAccess, nil
	}
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/asynkron/Faktorial/installation":
			json.NewEncoder(w).Encode(githubInstallation{ID: 123})
		case "/app/installations/123/access_tokens":
			json.NewEncoder(w).Encode(installationAccessToken{Token: "short", ExpiresAt: time.Now().Add(time.Hour), Permissions: map[string]string{"contents": "write", "pull_requests": "write", "issues": "write", "checks": "read", "statuses": "read"}})
		default:
			t.Errorf("unexpected github path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer github.Close()
	old := githubAPI
	githubAPI = github.URL
	defer func() { githubAPI = old }()
	rec := postProjectSource(t, s, "/api/github/project-source/token", "opaque", "asynkron/Faktorial", "https://app.faktorial.ai/projects/inmem")
	if rec.Code != http.StatusOK || checks != 1 {
		t.Fatalf("status=%d checks=%d body=%s", rec.Code, checks, rec.Body.String())
	}
	var body struct {
		Repo, Project, Access, Token string
		Permissions                  map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Repo != "asynkron/Faktorial" || body.Project != "https://app.faktorial.ai/projects/inmem" || body.Access != workerBuildAccess || body.Token != "short" || body.Permissions["checks"] != "read" || body.Permissions["statuses"] != "read" {
		t.Fatalf("response %#v", body)
	}
}

func TestProjectSourceRenewalRejectsWrongProjectBeforeGitHub(t *testing.T) {
	called := false
	s := projectSourceTestServer(t)
	s.projectSourceCredentialUser = func(context.Context, string, string, string, string) (int64, bool, error) {
		called = true
		return 0, false, nil
	}
	rec := postProjectSource(t, s, "/api/github/project-source/token", "opaque", "asynkron/Faktorial", "https://app.faktorial.ai/projects/other")
	if rec.Code != http.StatusForbidden || !called {
		t.Fatalf("status=%d credential_lookup=%v", rec.Code, called)
	}
}

func TestRepositoryLoginGrantRequiresGitHubPushAuthorization(t *testing.T) {
	s := projectSourceTestServer(t)
	stored := false
	s.repositoryWriteAuthorized = func(context.Context, string, string, string) (bool, error) { return false, nil }
	s.repositoryGrantStored = func(context.Context, int64, string, string, string) error { stored = true; return nil }
	if err := s.establishRepositoryGrant(context.Background(), 9, "ephemeral", "asynkron", "Faktorial", workerBuildAccess); err == nil || stored {
		t.Fatalf("err=%v stored=%v", err, stored)
	}
	s.repositoryWriteAuthorized = func(context.Context, string, string, string) (bool, error) { return true, nil }
	if err := s.establishRepositoryGrant(context.Background(), 9, "ephemeral", "asynkron", "Faktorial", workerBuildAccess); err != nil || !stored {
		t.Fatalf("err=%v stored=%v", err, stored)
	}
}

func projectSourceTestServer(t *testing.T) *server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &server{cfg: &config{GitHubAppID: "42", GitHubPrivateKey: key, DatabaseURL: "configured"}, httpClient: http.DefaultClient, sessionUser: func(context.Context, string) (*githubUser, error) { return &githubUser{ID: 9}, nil }}
}
func postProjectSource(t *testing.T, s *server, path, bearer, repo, project string) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"repo": repo, "project": project})
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	if path == "/api/github/project-source" {
		s.handleAPIProjectSource(rec, req)
	} else {
		s.handleAPIProjectSourceToken(rec, req)
	}
	return rec
}
