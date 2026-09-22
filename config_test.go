package eudiapiregistration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"

	"azugo.io/core/validation"
)

// TestConfigurationBindEnv: the two service-specific env bindings land in
// viper under their mapstructure keys.
func TestConfigurationBindEnv(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://registration_api_public:x@localhost:5432/verifier")
	t.Setenv("ADMIN_API_KEY", "s3cret-admin-key")

	v := viper.New()
	v.AutomaticEnv()
	c := NewConfiguration()
	c.Bind("", v)

	qt.Check(t, qt.Equals(v.GetString("postgres_dsn"), "postgres://registration_api_public:x@localhost:5432/verifier"))
	qt.Check(t, qt.Equals(v.GetString("admin_api_key"), "s3cret-admin-key"))
}

// TestConfigurationSecretFileConvention asserts both opaque secrets — the
// already-wired ADMIN_API_KEY and the newly-wired POSTGRES_DSN — honor the
// platform's Vault-agent <NAME>_FILE secret-file convention (loadSecret →
// LoadRemoteSecret), and that an explicit plain env var still overrides the
// file. LoadRemoteSecret trims whitespace, so a trailing newline is dropped.
func TestConfigurationSecretFileConvention(t *testing.T) {
	dir := t.TempDir()
	dsnFile := filepath.Join(dir, "dsn")
	keyFile := filepath.Join(dir, "key")
	qt.Assert(t, qt.IsNil(os.WriteFile(dsnFile, []byte("postgres://registration_api_public:filepw@db/verifier\n"), 0o600)))
	qt.Assert(t, qt.IsNil(os.WriteFile(keyFile, []byte("  key-from-file\n"), 0o600)))

	t.Setenv("POSTGRES_DSN_FILE", dsnFile)
	t.Setenv("ADMIN_API_KEY_FILE", keyFile)

	v := viper.New()
	NewConfiguration().Bind("", v)

	qt.Check(t, qt.Equals(v.GetString("postgres_dsn"), "postgres://registration_api_public:filepw@db/verifier"))
	qt.Check(t, qt.Equals(v.GetString("admin_api_key"), "key-from-file"))

	// Explicit plain env wins over the _FILE default.
	t.Setenv("POSTGRES_DSN", "postgres://from-env@db/verifier")
	v2 := viper.New()
	NewConfiguration().Bind("", v2)
	qt.Check(t, qt.Equals(v2.GetString("postgres_dsn"), "postgres://from-env@db/verifier"))
}

// validCompleteConfig returns a Configuration with every required field
// populated. The whole surface is POSTGRES_DSN + ADMIN_API_KEY on top of the
// kit base.
func validCompleteConfig() *Configuration {
	cfg := NewConfiguration()
	cfg.ServiceName = "eudi-api-registration"
	cfg.PostgresDSN = "postgres://registration_api_public@db/verifier"
	cfg.AdminAPIKey = "s3cret-admin-key"
	return cfg
}

// TestConfigurationValidateMissingRequiredField asserts a freshly constructed
// Configuration (every field at its zero value) fails validation — the
// fail-closed startup contract: this service must refuse to boot rather than
// run with an empty Postgres DSN / admin API key.
func TestConfigurationValidateMissingRequiredField(t *testing.T) {
	cfg := NewConfiguration()
	err := cfg.Validate(validation.New())
	qt.Assert(t, qt.IsNotNil(err))
}

// TestConfigurationValidatePassesWhenComplete is the positive counterpart.
func TestConfigurationValidatePassesWhenComplete(t *testing.T) {
	err := validCompleteConfig().Validate(validation.New())
	qt.Assert(t, qt.IsNil(err))
}

// TestAdminAPIKeyRequiredValidation is the fail-closed canary: AdminAPIKey is
// UNCONDITIONALLY `validate:"required"` (the service itself IS the admin API),
// so there is no "disabled, no key needed" branch to assert: only "missing ->
// fail closed" and "present -> valid".
func TestAdminAPIKeyRequiredValidation(t *testing.T) {
	// missing AdminAPIKey -> fail closed, even though every other required
	// field is populated.
	c := validCompleteConfig()
	c.AdminAPIKey = ""
	qt.Assert(t, qt.IsNotNil(c.Validate(validation.New())))

	// present -> valid.
	c = validCompleteConfig()
	qt.Assert(t, qt.IsNil(c.Validate(validation.New())))
}

// TestConfigurationValidateMissingPostgresDSN pins PostgresDSN's own
// `required` tag independently of AdminAPIKey's, so a future refactor can't
// accidentally satisfy validation by relying on the other field alone.
func TestConfigurationValidateMissingPostgresDSN(t *testing.T) {
	c := validCompleteConfig()
	c.PostgresDSN = ""
	qt.Assert(t, qt.IsNotNil(c.Validate(validation.New())))
}
