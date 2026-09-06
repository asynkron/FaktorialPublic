package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGitHubTokenRequiresRepositoryGrantBeforeCallingGitHub(t *testing.T) {
	githubCalled := false
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		githubCalled = true
		http.Error(w, "unexpected GitHub call", http.StatusInternalServerError)
	}))
	defer github.Close()

	old := githubAPI
	githubAPI = github.URL
	defer func() { githubAPI = old }()

	s := &server{
		cfg: &config{
			GitHubAppID:      "42",
			GitHubPrivateKey: &rsa.PrivateKey{},
			DatabaseURL:      "configured",
		},
		httpClient: github.Client(),
		sessionUser: func(context.Context, string) (*githubUser, error) {
			return &githubUser{ID: 7, Login: "unauthorized-user"}, nil
		},
		repositoryTokenAuthorized: func(_ context.Context, userID int64, owner, repo, access string) (bool, error) {
			if userID != 7 || owner != "asynkron" || repo != "Faktorial" || access != "contents-read" {
				t.Fatalf("authorization input = %d %q/%q %q", userID, owner, repo, access)
			}
			return false, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/github/token", bytes.NewBufferString(`{"repo":"asynkron/Faktorial","access":"contents-read"}`))
	req.Header.Set("Authorization", "Bearer session")
	rec := httptest.NewRecorder()

	s.handleAPIGitHubToken(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if githubCalled {
		t.Fatal("unauthorized request reached GitHub")
	}
	if !strings.Contains(rec.Body.String(), "repository is not authorized") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestReadTokenRequestsSingleRepositoryAndRejectsExcessPermissions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		permissions map[string]string
		accepted    bool
	}{
		{"contents", map[string]string{"contents": "read"}, true},
		{"implicit metadata", map[string]string{"contents": "read", "metadata": "read"}, true},
		{"missing confirmation", nil, false},
		{"write contents", map[string]string{"contents": "write"}, false},
		{"additional read", map[string]string{"contents": "read", "issues": "read"}, false},
		{"additional write", map[string]string{"contents": "read", "issues": "write"}, false},
		{"metadata write", map[string]string{"contents": "read", "metadata": "write"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.Method != http.MethodPost || r.URL.Path != "/app/installations/123/access_tokens" {
					t.Errorf("unexpected GitHub request %s %s", r.Method, r.URL.Path)
				}
				var request map[string]any
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				want := map[string]any{"repositories": []any{"Faktorial"}, "permissions": map[string]any{"contents": "read"}}
				if !reflect.DeepEqual(request, want) {
					t.Errorf("request = %#v", request)
				}
				json.NewEncoder(w).Encode(installationAccessToken{Token: "fixture-token", ExpiresAt: time.Now().Add(time.Hour), Permissions: tc.permissions})
			}))
			defer github.Close()
			old := githubAPI
			githubAPI = github.URL
			defer func() { githubAPI = old }()
			s := &server{cfg: &config{GitHubAppID: "42", GitHubPrivateKey: key}, httpClient: github.Client()}
			result, err := s.mintInstallationTokenWithAccess(context.Background(), 123, "Faktorial", "contents-read")
			if !called || (err == nil) != tc.accepted {
				t.Fatalf("called=%v accepted=%v error=%v", called, tc.accepted, err)
			}
			if tc.accepted && (result.Token != "fixture-token" || !reflect.DeepEqual(result.Permissions, tc.permissions)) {
				t.Fatal("accepted token changed")
			}
			if !tc.accepted && result != nil {
				t.Fatal("rejected token leaked to caller")
			}
			called = false
			if _, err := s.mintInstallationTokenWithAccess(context.Background(), 123, "Faktorial", "unknown"); err == nil || called {
				t.Fatal("unknown access reached GitHub")
			}
		})
	}
}
