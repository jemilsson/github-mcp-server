// Package auth provides GitHub App authentication support for the MCP server.
// It handles JWT signing, installation token exchange, and automatic token refresh.
// Supports multiple installations, automatically discovering them and routing
// API requests to the correct installation based on the repository owner.
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

// installationTokenResponse represents the GitHub API response for creating
// an installation access token.
type installationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// installationResponse represents a single installation from GET /app/installations.
type installationResponse struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
	} `json:"account"`
}

// cachedToken holds a token and its expiry for a single installation.
type cachedToken struct {
	token  string
	expiry time.Time
}

// AppTokenProvider generates and caches GitHub App installation tokens.
// It discovers all installations automatically and routes requests to the
// correct installation based on the repository owner.
type AppTokenProvider struct {
	appID      int64
	privateKey *rsa.PrivateKey
	apiBaseURL string

	mu             sync.Mutex
	// ownerToInstall maps lowercase account login to installation ID
	ownerToInstall map[string]int64
	// tokenCache maps installation ID to cached token
	tokenCache     map[int64]*cachedToken
	// defaultInstallID is used for requests where we can't determine the owner
	defaultInstallID int64
	// installationsDiscovered tracks whether we've fetched installations yet
	installationsDiscovered bool
}

// NewAppTokenProvider creates a new AppTokenProvider from the given parameters.
// The privateKeyPath should point to a PEM-encoded RSA private key file
// downloaded from the GitHub App settings page.
// If installationID is non-zero, it is used as the sole (and default) installation.
// If installationID is zero, installations are auto-discovered on first use.
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

	p := &AppTokenProvider{
		appID:          appID,
		privateKey:     key,
		apiBaseURL:     apiBaseURL,
		ownerToInstall: make(map[string]int64),
		tokenCache:     make(map[int64]*cachedToken),
	}

	// If a specific installation ID was provided, use it directly
	if installationID != 0 {
		p.defaultInstallID = installationID
		p.installationsDiscovered = true
	}

	return p, nil
}

// Token returns a valid installation access token for the default installation.
// This satisfies the TokenProvider interface for requests where the owner is unknown.
func (p *AppTokenProvider) Token() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureInstallations(); err != nil {
		return "", err
	}

	if p.defaultInstallID == 0 {
		return "", fmt.Errorf("no installations found for this GitHub App")
	}

	return p.tokenForInstallation(p.defaultInstallID)
}

// TokenForOwner returns a valid installation access token for the given owner.
// If no installation is found for the owner, falls back to the default installation.
func (p *AppTokenProvider) TokenForOwner(owner string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureInstallations(); err != nil {
		return "", err
	}

	installID, ok := p.ownerToInstall[strings.ToLower(owner)]
	if !ok {
		if p.defaultInstallID == 0 {
			return "", fmt.Errorf("no installation found for owner %q and no default installation available", owner)
		}
		installID = p.defaultInstallID
	}

	return p.tokenForInstallation(installID)
}

// ensureInstallations discovers installations if not already done. Must be called with mu held.
func (p *AppTokenProvider) ensureInstallations() error {
	if p.installationsDiscovered {
		return nil
	}

	installations, err := p.fetchInstallations()
	if err != nil {
		return fmt.Errorf("discovering installations: %w", err)
	}

	if len(installations) == 0 {
		return fmt.Errorf("GitHub App %d has no installations", p.appID)
	}

	for _, inst := range installations {
		login := strings.ToLower(inst.Account.Login)
		p.ownerToInstall[login] = inst.ID
	}

	// Use the first installation as default
	p.defaultInstallID = installations[0].ID
	p.installationsDiscovered = true

	return nil
}

// fetchInstallations calls GET /app/installations to discover all installations.
func (p *AppTokenProvider) fetchInstallations() ([]installationResponse, error) {
	jwtToken, err := p.createJWT()
	if err != nil {
		return nil, fmt.Errorf("creating JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations", p.apiBaseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching installations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var installations []installationResponse
	if err := json.NewDecoder(resp.Body).Decode(&installations); err != nil {
		return nil, fmt.Errorf("decoding installations response: %w", err)
	}

	return installations, nil
}

// tokenForInstallation returns a cached or fresh token for the given installation ID.
// Must be called with mu held.
func (p *AppTokenProvider) tokenForInstallation(installID int64) (string, error) {
	if cached, ok := p.tokenCache[installID]; ok {
		// Refresh 5 minutes before expiry
		if cached.token != "" && time.Now().Before(cached.expiry.Add(-5*time.Minute)) {
			return cached.token, nil
		}
	}

	token, expiry, err := p.refreshToken(installID)
	if err != nil {
		return "", err
	}

	p.tokenCache[installID] = &cachedToken{token: token, expiry: expiry}
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
func (p *AppTokenProvider) refreshToken(installID int64) (string, time.Time, error) {
	jwtToken, err := p.createJWT()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.apiBaseURL, installID)
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
