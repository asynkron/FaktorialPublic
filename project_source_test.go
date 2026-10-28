package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestRepositoryLoginGrantRequiresGitHubPermissionForRequestedAccess(t *testing.T) {
	for _, tc := range []struct {
		name      string
		access    string
		body      string
		status    int
		transport bool
		accepted  bool
	}{
		{name: "read-only user", access: "contents-read", body: `{"full_name":"asynkron/FaktorialDemo","permissions":{"pull":true,"push":false}}`, accepted: true},
		{name: "read-only user cannot build", access: workerBuildAccess, body: `{"full_name":"asynkron/FaktorialDemo","permissions":{"pull":true,"push":false}}`},
		{name: "writer can build", access: workerBuildAccess, body: `{"full_name":"asynkron/FaktorialDemo","permissions":{"pull":true,"push":true}}`, accepted: true},
		{name: "writer can request read only", access: "contents-read", body: `{"full_name":"asynkron/FaktorialDemo","permissions":{"pull":true,"push":true}}`, accepted: true},
		{name: "read requires pull permission", access: "contents-read", body: `{"full_name":"asynkron/FaktorialDemo","permissions":{"pull":false,"push":true}}`},
		{name: "visible metadata is insufficient", access: "contents-read", body: `{"full_name":"asynkron/FaktorialDemo"}`},
		{name: "read rejects another repository", access: "contents-read", body: `{"full_name":"asynkron/Other","permissions":{"pull":true,"push":true}}`},
		{name: "build rejects another repository", access: workerBuildAccess, body: `{"full_name":"asynkron/Other","permissions":{"pull":true,"push":true}}`},
		{name: "read denies provider rejection", access: "contents-read", status: http.StatusForbidden, body: `{"full_name":"asynkron/FaktorialDemo","permissions":{"pull":true}}`},
		{name: "read denies malformed response", access: "contents-read", body: `not json`},
		{name: "read denies transport failure", access: "contents-read", transport: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/login?repo=asynkron%2FFaktorialDemo&access="+tc.access, nil)
			owner, name, access, err := loginRepositoryRequest(req)
			if err != nil || owner != "asynkron" || name != "FaktorialDemo" || access != tc.access {
				t.Fatalf("repository login selection = %q/%q %q, %v", owner, name, access, err)
			}
			called, stored := false, false
			s := &server{
				httpClient: &http.Client{Transport: repositoryPermissionTransport(func(r *http.Request) (*http.Response, error) {
					called = true
					if r.Method != http.MethodGet || r.URL.Path != "/repos/asynkron/FaktorialDemo" || r.Header.Get("Authorization") != "Bearer ephemeral" {
						t.Fatalf("unexpected repository permission request: %s %s", r.Method, r.URL.Path)
					}
					if tc.transport {
						return nil, errors.New("fixture transport failure")
					}
					status := tc.status
					if status == 0 {
						status = http.StatusOK
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
				})},
				repositoryGrantStored: func(_ context.Context, id int64, owner, name, access string) error {
					if id != 9 || owner != "asynkron" || name != "FaktorialDemo" || access != tc.access {
						t.Fatalf("stored grant = %d %s/%s %s", id, owner, name, access)
					}
					stored = true
					return nil
				},
			}
			err = s.establishRepositoryGrant(t.Context(), 9, "ephemeral", owner, name, access)
			if !called || stored != tc.accepted || (err == nil) != tc.accepted {
				t.Fatalf("permission check called=%v stored=%v accepted=%v error=%v", called, stored, tc.accepted, err)
			}
		})
	}
}

func TestRepositoryLoginRejectsUnsupportedGrantAccess(t *testing.T) {
	for _, access := range []string{"", "legacy", "contents-write", "unknown"} {
		t.Run("access="+access, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/login?repo=asynkron%2FFaktorialDemo&access="+access, nil)
			if _, _, _, err := loginRepositoryRequest(req); err == nil {
				t.Fatal("unsupported repository login access was accepted")
			}
			stored := false
			s := &server{repositoryGrantStored: func(context.Context, int64, string, string, string) error {
				stored = true
				return nil
			}}
			if err := s.establishRepositoryGrant(t.Context(), 9, "ephemeral", "asynkron", "FaktorialDemo", access); err == nil || stored {
				t.Fatalf("unsupported access grant error=%v stored=%v", err, stored)
			}
		})
	}
}

type repositoryPermissionTransport func(*http.Request) (*http.Response, error)

func (transport repositoryPermissionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
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
