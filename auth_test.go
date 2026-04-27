package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseRepo(t *testing.T) {
	owner, name, err := parseRepo(" Frinima/SvenskCater ")
	if err != nil {
		t.Fatalf("parseRepo() error = %v", err)
	}
	if owner != "Frinima" || name != "SvenskCater" {
		t.Fatalf("parseRepo() = %q/%q", owner, name)
	}
	for _, input := range []string{"", "owner", "owner/repo/extra", "owner /repo", "owner/re po"} {
		if _, _, err := parseRepo(input); err == nil {
			t.Fatalf("parseRepo(%q) error = nil", input)
		}
	}
}

func TestGitHubInstallationTokenFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var sawRepoLookup bool
	var sawTokenMint bool
	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Fatalf("missing bearer auth: %q", got)
		}
		switch r.URL.Path {
		case "/repos/Frinima/SvenskCater/installation":
			sawRepoLookup = true
			_ = json.NewEncoder(w).Encode(githubInstallation{ID: 123})
		case "/app/installations/123/access_tokens":
			sawTokenMint = true
			if r.Method != http.MethodPost {
				t.Fatalf("mint method = %s", r.Method)
			}
			var req struct {
				Repositories []string `json:"repositories"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if len(req.Repositories) != 1 || req.Repositories[0] != "SvenskCater" {
				t.Fatalf("repositories = %#v", req.Repositories)
			}
			_, _ = w.Write([]byte(`{"token":"ghs_short","expires_at":"` + expiresAt + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer github.Close()
	oldGitHubAPI := githubAPI
	githubAPI = github.URL
	defer func() { githubAPI = oldGitHubAPI }()

	s := &server{
		cfg: &config{
			GitHubAppID:      "42",
			GitHubPrivateKey: key,
		},
		httpClient: github.Client(),
	}
	installation, err := s.fetchRepoInstallation(context.Background(), "Frinima", "SvenskCater")
	if err != nil {
		t.Fatalf("fetchRepoInstallation() error = %v", err)
	}
	token, err := s.mintInstallationAccessToken(context.Background(), installation.ID, "SvenskCater")
	if err != nil {
		t.Fatalf("mintInstallationAccessToken() error = %v", err)
	}
	if token.Token != "ghs_short" {
		t.Fatalf("token = %q", token.Token)
	}
	if !sawRepoLookup || !sawTokenMint {
		t.Fatalf("sawRepoLookup=%v sawTokenMint=%v", sawRepoLookup, sawTokenMint)
	}
}

func TestGitHubTokenReturnsInstallURLWhenAppCannotSeeRepo(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer github.Close()
	oldGitHubAPI := githubAPI
	githubAPI = github.URL
	defer func() { githubAPI = oldGitHubAPI }()

	s := &server{
		cfg: &config{
			GitHubAppID:      "42",
			GitHubPrivateKey: key,
		},
		httpClient: github.Client(),
	}
	req := httptest.NewRequest(http.MethodPost, "/api/github/token", bytes.NewBufferString(`{"repo":"Frinima/SvenskCater"}`))
	req.Header.Set("Authorization", "Bearer ignored")
	rec := httptest.NewRecorder()

	installation, err := s.fetchRepoInstallation(req.Context(), "Frinima", "SvenskCater")
	if err == nil || installation != nil {
		t.Fatalf("fetchRepoInstallation() = %#v, %v; want error", installation, err)
	}
	writeJSON(rec, http.StatusForbidden, map[string]string{
		"error":       "github app is not installed for this repository",
		"install_url": githubAppInstallURL,
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), githubAppInstallURL) {
		t.Fatalf("body missing install url: %s", rec.Body.String())
	}
}
