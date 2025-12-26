package mj3gc

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

const accessProviderType = "mj3gc-api-key"

// EnsureAccessProvider injects the mj3gc access provider into the config if missing.
func EnsureAccessProvider(cfg *config.Config) {
	if cfg == nil {
		return
	}
	for _, provider := range cfg.Access.Providers {
		if strings.EqualFold(strings.TrimSpace(provider.Type), accessProviderType) {
			return
		}
	}
	cfg.Access.Providers = append(cfg.Access.Providers, sdkconfig.AccessProvider{
		Name: "mj3gc",
		Type: accessProviderType,
	})
}
