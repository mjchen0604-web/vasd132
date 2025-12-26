package mj3gc

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
)

// ResolveDataPath returns the persistent data path for mj3gc user/key storage.
func ResolveDataPath(cfg *config.Config, configFilePath string) string {
	if override := strings.TrimSpace(os.Getenv("MJ3GC_DATA_PATH")); override != "" {
		return filepath.Clean(override)
	}

	if cfg != nil {
		if resolved, err := util.ResolveAuthDir(cfg.AuthDir); err == nil && strings.TrimSpace(resolved) != "" {
			return filepath.Join(resolved, "mj3gc-data.json")
		}
	}

	if base := util.WritablePath(); strings.TrimSpace(base) != "" {
		return filepath.Join(base, "mj3gc-data.json")
	}

	configFilePath = strings.TrimSpace(configFilePath)
	if configFilePath != "" {
		return filepath.Join(filepath.Dir(configFilePath), "mj3gc-data.json")
	}

	return filepath.Join(".", "mj3gc-data.json")
}
