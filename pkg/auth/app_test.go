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

	t.Run("valid config", func(t *testing.T) {
		provider, err := NewAppTokenProvider(12345, 67890, keyPath, "")
		require.NoError(t, err)
		assert.Equal(t, "https://api.github.com", provider.apiBaseURL)
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

func TestAppTokenProvider_Token(t *testing.T) {
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
	// Override the API URL to point to the test server
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
