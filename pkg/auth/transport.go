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

// DynamicBearerTransport is an http.RoundTripper that resolves the bearer
// token on every request via a TokenProvider. This supports GitHub App
// installation tokens which expire and need periodic refresh.
type DynamicBearerTransport struct {
	Transport http.RoundTripper
	Provider  TokenProvider
}

func (t *DynamicBearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.Provider.Token()
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
