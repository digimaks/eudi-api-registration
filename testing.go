//go:build testhelpers

package eudiapiregistration

import (
	"testing"

	"github.com/digimaks/eudi-api-registration/internal/registrydb"
)

// NewTestApp boots the app with a placeholder POSTGRES_DSN (init()'s
// pgxpool.New never dials eagerly, so this is harmless) and
// ADMIN_API_KEY=test-admin-key already set — no test needs to seed the
// admin key itself, and the admin surface is always on. Boots with a fresh
// registrydb.Fake already installed (SetStoreForTest) so no test may let a
// real query reach the placeholder POSTGRES_DSN; a test that needs a specific
// pre-seeded Fake instance can call SetStoreForTest again afterward.
func NewTestApp(tb testing.TB) *App {
	tb.Helper()

	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("SERVICE_NAME", "eudi-api-registration")
	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("POSTGRES_DSN", "postgres://registration_api_public:x@127.0.0.1:1/verifier")
	tb.Setenv("ADMIN_API_KEY", "test-admin-key")

	app, err := New(nil, "0.0.0-test")
	if err != nil {
		tb.Fatalf("eudiapiregistration.NewTestApp: %v", err)
	}
	tb.Cleanup(func() { app.db.Close() })
	app.SetStoreForTest(registrydb.NewFake())
	return app
}

// SetStoreForTest overrides the registrydb.Store (the fake-store seam) —
// route tests call this with registrydb.NewFake() and keep the returned
// *registrydb.Fake to seed clients and inspect its state; production's
// pgx-backed Store wired by init() would otherwise dial the deliberately
// unreachable POSTGRES_DSN on first real query.
func (a *App) SetStoreForTest(s registrydb.Store) {
	a.store = s
}
