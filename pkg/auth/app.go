// Package auth provides GitHub App authentication support for the MCP server.
// It handles JWT signing, installation token exchange, and automatic token refresh.
package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppTokenProvider generates and caches GitHub App installation tokens.
// It handles JWT creation, token exchange, and automatic refresh before expiry.
type AppTokenProvider struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey
	apiBaseURL     string

	mu           sync.Mutex
	cachedToken  string
	cachedExpiry time.Time
}

// installationTokenResponse represents the GitHub API response for creating
// an installation access token.
type installationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewAppTokenProvider creates a new AppTokenProvider from the given parameters.
// The privateKeyPath should point to a PEM-encoded RSA private key file
// downloaded from the GitHub App settings page.
func NewAppTokenProvider(appID, installationID int64, privateKeyPath string, host string) (*AppTokenProvider, error) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key file")
	}

	var key *rsa.PrivateKey

	// Try PKCS#1 first, then PKCS#8
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parsing private key (tried PKCS#1 and PKCS#8): %w", err2)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	apiBaseURL := "https://api.github.com"
	if host != "" && host != "github.com" {
		apiBaseURL = fmt.Sprintf("https://%s/api/v3", host)
	}

	return &AppTokenProvider{
		appID:          appID,
		installationID: installationID,
		privateKey:     key,
		apiBaseURL:     apiBaseURL,
	}, nil
}

// Token returns a valid installation access token, refreshing if necessary.
// Tokens are cached and refreshed 5 minutes before expiry to avoid
// using expired tokens during long-running operations.
func (p *AppTokenProvider) Token() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Refresh 5 minutes before expiry
	if p.cachedToken != "" && time.Now().Before(p.cachedExpiry.Add(-5*time.Minute)) {
		return p.cachedToken, nil
	}

	token, expiry, err := p.refreshToken()
	if err != nil {
		return "", err
	}

	p.cachedToken = token
	p.cachedExpiry = expiry
	return token, nil
}

// createJWT creates a signed JWT for GitHub App authentication.
func (p *AppTokenProvider) createJWT() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:    fmt.Sprintf("%d", p.appID),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(p.privateKey)
}

// refreshToken exchanges a JWT for a new installation access token.
func (p *AppTokenProvider) refreshToken() (string, time.Time, error) {
	jwtToken, err := p.createJWT()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.apiBaseURL, p.installationID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("exchanging JWT for installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenResp installationTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("decoding token response: %w", err)
	}

	return tokenResp.Token, tokenResp.ExpiresAt, nil
}
