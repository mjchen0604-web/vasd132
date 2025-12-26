package mj3gcaccess

import (
	"context"
	"net/http"
	"strings"
	"sync"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/mj3gc"
)

const providerType = "mj3gc-api-key"

var registerOnce sync.Once

func Register() {
	registerOnce.Do(func() {
		sdkaccess.RegisterProvider(providerType, newProvider)
	})
}

type provider struct {
	name string
}

func newProvider(cfg *sdkconfig.AccessProvider, _ *sdkconfig.SDKConfig) (sdkaccess.Provider, error) {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = providerType
	}
	return &provider{name: name}, nil
}

func (p *provider) Identifier() string {
	if p == nil || p.name == "" {
		return providerType
	}
	return p.name
}

func (p *provider) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, error) {
	if p == nil {
		return nil, sdkaccess.ErrNotHandled
	}
	if r == nil {
		return nil, sdkaccess.ErrNoCredentials
	}

	value, source := extractAPIKey(r)
	if value == "" {
		return nil, sdkaccess.ErrNoCredentials
	}

	store := mj3gc.DefaultStore()
	apiKey, ok := store.FindAPIKey(value)
	if !ok {
		return nil, sdkaccess.ErrInvalidCredential
	}
	if !apiKey.Enabled {
		return nil, sdkaccess.ErrInvalidCredential
	}
	if !apiKey.CompatibilityMode && !isStrictSource(source) {
		return nil, sdkaccess.ErrInvalidCredential
	}

	metadata := map[string]string{}
	if apiKey.UserID != "" {
		metadata["user_id"] = apiKey.UserID
	}
	if apiKey.Label != "" {
		metadata["label"] = apiKey.Label
	}

	return &sdkaccess.Result{
		Provider:  p.Identifier(),
		Principal: apiKey.Key,
		Metadata:  metadata,
	}, nil
}

func extractAPIKey(r *http.Request) (string, string) {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1]), "authorization"
		}
		return strings.TrimSpace(authHeader), "authorization"
	}

	if v := strings.TrimSpace(r.Header.Get("X-Api-Key")); v != "" {
		return v, "x-api-key"
	}
	if v := strings.TrimSpace(r.Header.Get("X-Goog-Api-Key")); v != "" {
		return v, "x-goog-api-key"
	}
	if v := strings.TrimSpace(r.Header.Get("X-API-Key")); v != "" {
		return v, "x-api-key"
	}

	if r.URL != nil {
		if v := strings.TrimSpace(r.URL.Query().Get("key")); v != "" {
			return v, "query-key"
		}
		if v := strings.TrimSpace(r.URL.Query().Get("auth_token")); v != "" {
			return v, "query-auth-token"
		}
	}
	return "", ""
}

func isStrictSource(source string) bool {
	switch source {
	case "authorization", "x-api-key":
		return true
	default:
		return false
	}
}
