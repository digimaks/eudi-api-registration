package eudiapiregistration

import (
	pkconfig "github.com/gmb-lib/go-platform-kit/config"

	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration embeds the kit base config (SERVICE_NAME, ENVIRONMENT, LOG_*,
// METRICS_ENABLED, OTEL_*, RATELIMIT_* …). The whole surface is POSTGRES_DSN +
// ADMIN_API_KEY — no Valkey, no OIDC, no legacy fields.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// PostgresDSN connects as the EXECUTE-only registration_api_public role.
	// Secret (carries the DB password): supports the POSTGRES_DSN_FILE form.
	PostgresDSN string `mapstructure:"postgres_dsn" validate:"required"`

	// AdminAPIKey is the X-API-Key value the API constant-time-compares
	// against (apiauth.go). REQUIRED at boot — this service IS the API, so
	// there is no unguarded mode (fail closed). A single opaque deployment-wide
	// token, loaded via the Vault-agent ADMIN_API_KEY_FILE convention, NOT
	// hashed.
	AdminAPIKey string `mapstructure:"admin_api_key" validate:"required"`
}

// NewConfiguration returns a Configuration with the embedded kit base
// configuration initialized.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// Bind registers environment-variable bindings with viper; it must call the
// embedded BaseConfiguration.Bind first.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)

	// Secrets: prefer the Vault-agent <NAME>_FILE convention (loadSecret sets
	// a viper default from the file's content); an explicit plain env var
	// still overrides it. POSTGRES_DSN carries the DB password; ADMIN_API_KEY
	// is the admin X-API-Key.
	loadSecret(v, "postgres_dsn", "POSTGRES_DSN")
	loadSecret(v, "admin_api_key", "ADMIN_API_KEY")

	_ = v.BindEnv("postgres_dsn", "POSTGRES_DSN")
	_ = v.BindEnv("admin_api_key", "ADMIN_API_KEY")
}

// loadSecret resolves a secret from the secret store (Vault agent ->
// <NAME>_FILE) and registers it as a viper default, so an explicit plain env
// var still overrides it.
func loadSecret(v *viper.Viper, key, name string) {
	if secret, err := corecfg.LoadRemoteSecret(name); err == nil && secret != "" {
		v.SetDefault(key, secret)
	}
}

// Validate validates the embedded base configuration, then this service's own
// fields. AdminAPIKey's `required` tag is the fail-closed boot check: the
// service never starts with the API unguarded.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	return valid.Struct(c)
}
