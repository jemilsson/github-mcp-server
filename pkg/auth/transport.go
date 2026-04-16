package auth

import (
	"fmt"
	"net/http"
	"strings"

	ghcontext "github.com/github/github-mcp-server/pkg/context"
	headers "github.com/github/github-mcp-server/pkg/http/headers"
)

// TokenProvider is implemented by anything that can supply a bearer token.
type TokenProvider interface {
	Token() (string, error)
}

// OwnerAwareTokenProvider extends TokenProvider with the ability to return
// a token scoped to a specific repository owner (user or org).
type OwnerAwareTokenProvider interface {
	TokenProvider
	TokenForOwner(owner string) (string, error)
}

// DynamicBearerTransport is an http.RoundTripper that resolves the bearer
// token on every request via a TokenProvider. When the provider implements
// OwnerAwareTokenProvider, it extracts the owner from the request URL and
// uses a token scoped to that owner's installation.
type DynamicBearerTransport struct {
	Transport http.RoundTripper
	Provider  TokenProvider
}

func (t *DynamicBearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var token string
	var err error

	if ownerAware, ok := t.Provider.(OwnerAwareTokenProvider); ok {
		if owner := extractOwner(req.URL.Path); owner != "" {
			token, err = ownerAware.TokenForOwner(owner)
		} else {
			token, err = t.Provider.Token()
		}
	} else {
		token, err = t.Provider.Token()
	}

	if err != nil {
		return nil, fmt.Errorf("obtaining bearer token: %w", err)
	}

	req = req.Clone(req.Context())
	req.Header.Set(headers.AuthorizationHeader, "Bearer "+token)

	if features := ghcontext.GetGraphQLFeatures(req.Context()); len(features) > 0 {
		req.Header.Set(headers.GraphQLFeaturesHeader, strings.Join(features, ", "))
	}

	return t.Transport.RoundTrip(req)
}

// extractOwner extracts the repository owner or org from a GitHub API URL path.
// Returns empty string if the owner cannot be determined.
func extractOwner(path string) string {
	// Trim leading slash and split
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}

	// Match patterns that have an owner as the second path segment:
	// /repos/{owner}/{repo}/...
	// /orgs/{org}/...
	// /users/{user}/...
	switch parts[0] {
	case "repos":
		if len(parts) >= 3 {
			return parts[1]
		}
	case "orgs", "users":
		return parts[1]
	}

	return ""
}
