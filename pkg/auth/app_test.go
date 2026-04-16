package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}

	path := filepath.Join(t.TempDir(), "test-key.pem")
	err = os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	return path, key
}

func TestNewAppTokenProvider(t *testing.T) {
	keyPath, _ := generateTestKey(t)

	t.Run("valid config with installation ID", func(t *testing.T) {
		provider, err := NewAppTokenProvider(12345, 67890, keyPath, "")
		require.NoError(t, err)
		assert.Equal(t, "https://api.github.com", provider.apiBaseURL)
		assert.True(t, provider.installationsDiscovered)
		assert.Equal(t, int64(67890), provider.defaultInstallID)
	})

	t.Run("valid config without installation ID (auto-discover)", func(t *testing.T) {
		provider, err := NewAppTokenProvider(12345, 0, keyPath, "")
		require.NoError(t, err)
		assert.False(t, provider.installationsDiscovered)
		assert.Equal(t, int64(0), provider.defaultInstallID)
	})

	t.Run("github enterprise host", func(t *testing.T) {
		provider, err := NewAppTokenProvider(12345, 67890, keyPath, "github.example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://github.example.com/api/v3", provider.apiBaseURL)
	})

	t.Run("github.com host uses public API", func(t *testing.T) {
		provider, err := NewAppTokenProvider(12345, 67890, keyPath, "github.com")
		require.NoError(t, err)
		assert.Equal(t, "https://api.github.com", provider.apiBaseURL)
	})

	t.Run("missing key file", func(t *testing.T) {
		_, err := NewAppTokenProvider(12345, 67890, "/nonexistent/key.pem", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "reading private key")
	})

	t.Run("invalid key file", func(t *testing.T) {
		badPath := filepath.Join(t.TempDir(), "bad.pem")
		err := os.WriteFile(badPath, []byte("not a pem file"), 0600)
		require.NoError(t, err)
		_, err = NewAppTokenProvider(12345, 67890, badPath, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no PEM block found")
	})
}

func TestAppTokenProvider_Token_SingleInstallation(t *testing.T) {
	keyPath, _ := generateTestKey(t)

	fakeToken := "ghs_test_installation_token_abc123"
	expiresAt := time.Now().Add(1 * time.Hour)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "/app/installations/67890/access_tokens")
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
		assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))

		w.WriteHeader(http.StatusCreated)
		resp := installationTokenResponse{
			Token:     fakeToken,
			ExpiresAt: expiresAt,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider, err := NewAppTokenProvider(12345, 67890, keyPath, "")
	require.NoError(t, err)
	provider.apiBaseURL = server.URL

	t.Run("fetches token on first call", func(t *testing.T) {
		token, err := provider.Token()
		require.NoError(t, err)
		assert.Equal(t, fakeToken, token)
	})

	t.Run("returns cached token on second call", func(t *testing.T) {
		token, err := provider.Token()
		require.NoError(t, err)
		assert.Equal(t, fakeToken, token)
	})
}

func TestAppTokenProvider_TokenRefresh(t *testing.T) {
	keyPath, _ := generateTestKey(t)

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusCreated)
		resp := installationTokenResponse{
			Token:     fmt.Sprintf("ghs_token_%d", callCount),
			ExpiresAt: time.Now().Add(3 * time.Minute), // Expires in 3 minutes (inside the 5-min refresh window)
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider, err := NewAppTokenProvider(12345, 67890, keyPath, "")
	require.NoError(t, err)
	provider.apiBaseURL = server.URL

	// First call fetches
	token1, err := provider.Token()
	require.NoError(t, err)
	assert.Equal(t, "ghs_token_1", token1)

	// Second call should refresh because expiry is within 5-min window
	token2, err := provider.Token()
	require.NoError(t, err)
	assert.Equal(t, "ghs_token_2", token2)
	assert.Equal(t, 2, callCount)
}

func TestAppTokenProvider_AutoDiscovery(t *testing.T) {
	keyPath, _ := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/app/installations":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]installationResponse{
				{ID: 111, Account: struct {
					Login string `json:"login"`
				}{Login: "alice"}},
				{ID: 222, Account: struct {
					Login string `json:"login"`
				}{Login: "acme-org"}},
				{ID: 333, Account: struct {
					Login string `json:"login"`
				}{Login: "widgets-inc"}},
			})
		case r.Method == "POST" && r.URL.Path == "/app/installations/111/access_tokens":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(installationTokenResponse{
				Token:     "ghs_alice_token",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			})
		case r.Method == "POST" && r.URL.Path == "/app/installations/222/access_tokens":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(installationTokenResponse{
				Token:     "ghs_acme_org_token",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			})
		case r.Method == "POST" && r.URL.Path == "/app/installations/333/access_tokens":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(installationTokenResponse{
				Token:     "ghs_widgets_inc_token",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// installationID=0 triggers auto-discovery
	provider, err := NewAppTokenProvider(12345, 0, keyPath, "")
	require.NoError(t, err)
	provider.apiBaseURL = server.URL

	t.Run("Token returns default (first) installation token", func(t *testing.T) {
		token, err := provider.Token()
		require.NoError(t, err)
		assert.Equal(t, "ghs_alice_token", token)
	})

	t.Run("TokenForOwner returns correct token per owner", func(t *testing.T) {
		token, err := provider.TokenForOwner("alice")
		require.NoError(t, err)
		assert.Equal(t, "ghs_alice_token", token)

		token, err = provider.TokenForOwner("acme-org")
		require.NoError(t, err)
		assert.Equal(t, "ghs_acme_org_token", token)

		token, err = provider.TokenForOwner("widgets-inc")
		require.NoError(t, err)
		assert.Equal(t, "ghs_widgets_inc_token", token)
	})

	t.Run("TokenForOwner is case-insensitive", func(t *testing.T) {
		token, err := provider.TokenForOwner("Alice")
		require.NoError(t, err)
		assert.Equal(t, "ghs_alice_token", token)
	})

	t.Run("TokenForOwner falls back to default for unknown owner", func(t *testing.T) {
		token, err := provider.TokenForOwner("unknown-org")
		require.NoError(t, err)
		assert.Equal(t, "ghs_alice_token", token)
	})
}

func TestExtractOwner(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/repos/alice/my-repo/issues", "alice"},
		{"/repos/acme-org/backend/pulls", "acme-org"},
		{"/orgs/widgets-inc/repos", "widgets-inc"},
		{"/users/alice/repos", "alice"},
		{"/user", ""},
		{"/search/repositories", ""},
		{"/repos", ""},
		{"", ""},
		{"/", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractOwner(tt.path))
		})
	}
}
