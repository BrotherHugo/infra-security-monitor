package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads YAML from disk, parses it, and applies defaults.
// Validate is called separately.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing YAML %q: %w", path, err)
	}

	applyDefaults(&cfg)
	return cfg, nil
}
