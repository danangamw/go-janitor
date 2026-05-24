package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all runtime configuration. Precedence: CLI flag > env var > config file > default.
type Config struct {
	DryRun      bool          `mapstructure:"dry_run"`
	MaxAge      time.Duration `mapstructure:"max_age"`
	Severity    string        `mapstructure:"severity"`
	Concurrency int           `mapstructure:"concurrency"`
	Output      string        `mapstructure:"output"`
	OutputFile  string        `mapstructure:"output_file"`
	Webhook     string        `mapstructure:"webhook"`
	Socket      string        `mapstructure:"socket"`
	LogLevel    string        `mapstructure:"log_level"`
	ConfigFile  string        `mapstructure:"-"`
}

// Load reads configuration from the global viper instance (which already has
// CLI pflags bound by main), then overlays env vars and optionally a config file.
// Precedence: CLI flag > env var > config file > default.
func Load(cfgFile string) (*Config, error) {
	// Use the global viper so pflags bound in main are visible here.
	v := viper.GetViper()

	// Defaults — only applied when the key has no value from any higher-priority source.
	viper.SetDefault("dry_run", false)
	viper.SetDefault("max_age", "48h")
	viper.SetDefault("severity", "CRITICAL,HIGH")
	viper.SetDefault("concurrency", 5)
	viper.SetDefault("output", "text")
	viper.SetDefault("output_file", "")
	viper.SetDefault("webhook", "")
	viper.SetDefault("socket", "/var/run/docker.sock")
	viper.SetDefault("log_level", "info")

	// Env vars: JANITOR_MAX_AGE, JANITOR_WEBHOOK, etc.
	viper.SetEnvPrefix("JANITOR")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config file %q: %w", cfgFile, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}
	cfg.ConfigFile = cfgFile

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be >= 1, got %d", c.Concurrency)
	}
	if c.Output != "text" && c.Output != "json" {
		return fmt.Errorf("output must be 'text' or 'json', got %q", c.Output)
	}
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[strings.ToLower(c.LogLevel)] {
		return fmt.Errorf("log_level must be one of debug/info/warn/error, got %q", c.LogLevel)
	}
	return nil
}
