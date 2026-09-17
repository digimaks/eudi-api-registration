// Package eudiapiregistration is the headless client-registration admin API of
// the EUDI verifier. X-API-Key machine-to-machine surface over the shared
// registry schema; no HTML, no sessions, no Valkey. Public boundary:
// PublicErrors=true.
package eudiapiregistration

import (
	"context"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-platform-kit/platform"

	"github.com/dativa-lv/eudi-api-registration/internal/registrydb"
)

// App is the eudi-api-registration application container: it embeds *azugo.App and
// holds every service-level dependency. This is exactly what the headless
// admin API needs — config, the Postgres pool, and the registry bridge; no
// Valkey, no keys, no trust anchors, no sessions, no OIDC.
type App struct {
	*azugo.App

	config *Configuration
	db     *pgxpool.Pool
	store  registrydb.Store
}

// New builds the eudi-api-registration App: server.New wires Azugo, then init
// layers platform.Setup and the service's own dependencies on top.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Registration API",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	app := &App{App: a, config: config}
	if err := app.init(); err != nil {
		return nil, err
	}
	return app, nil
}

func (a *App) init() error {
	// Verifier taxonomy — every code this service produces, registered before
	// Setup, single site. Statuses outside the kit's built-in reason map need
	// explicit specs.
	// err:client:intendedUseRequired / err:client:ts5CheckFailed —
	// internal/lifecycle.Service's "-> active" activation precondition
	// (intended uses verified and ARF TS5 last check ok before templates/keys
	// are enabled). Same reason name and status as eudi-api-management's own
	// "intended-use-required" (a different process's registry, so no
	// collision) — this service raises these directly via pkerrors.NewProblem,
	// never through a DB envelope, since the precondition is enforced at the
	// API layer, not something registry.transition_client itself checks (the
	// legal-transition matrix is not re-implemented in Go — this is an
	// orthogonal check the store never makes).
	pkerrors.RegisterReason("intendedUseRequired", pkerrors.ReasonSpec{Status: 422, Title: "Intended use required"})
	// err:client:registrarIdentityRequired — "-> active" also requires the
	// registrar identity (registrar URL + assigned identifier) to be recorded:
	// it travels in every presentation request the client's sessions make, so
	// activating without it only moves the failure to the first session. Same
	// reason name and status as the session service's own, so an integrator
	// sees one code for one condition wherever it is caught.
	pkerrors.RegisterReason("registrarIdentityRequired", pkerrors.ReasonSpec{Status: 422, Title: "Client registrar identity required"})
	pkerrors.RegisterReason("ts5CheckFailed", pkerrors.ReasonSpec{Status: 422, Title: "ARF TS5 verification check failed"})
	// registry:illegal_transition — registrydb.Store.TransitionClient
	// (lifecycle matrix); same 409-for-illegal-state-transition convention as
	// eudi-api-management's "not-cancellable".
	pkerrors.RegisterReason("illegalTransition", pkerrors.ReasonSpec{Status: 409, Title: "Illegal client-lifecycle transition"})
	// err:api:invalidBody — the admin API's own request-body validation
	// (routes/api.go's apiCreateClient): malformed JSON or a missing required
	// field (e.g. CreateClientRequest.name), raised directly via
	// pkerrors.NewProblem since this is a wire-shape check on the admin API's
	// own DTO, never something registrydb.Store itself would reject
	// (CreateDraftClient takes name as a bare string with no not-empty
	// constraint of its own).
	pkerrors.RegisterReason("invalidBody", pkerrors.ReasonSpec{Status: 400, Title: "Invalid request body"})
	// err:api:registrationInvalid — the admin API's structured registration
	// endpoint (routes/api_registration.go's apiSetRegistration):
	// wizard.FormState.Build's own validation failure (missing intended use,
	// bad claim path, non-https privacy policy URI, incomplete
	// supervisory-authority contact, ...) surfaces as this 422.
	pkerrors.RegisterReason("registrationInvalid", pkerrors.ReasonSpec{Status: 422, Title: "Registration document invalid"})
	// err:registry:not_found — registry.* procedures raise their own not_found
	// reason, so this makes the wire code domain-specific (err:registry:not_found)
	// instead of the kit's generic built-in "Not found" bucket (which would
	// otherwise render as err:request:notFound, hiding which domain the id
	// belongs to). AllowBuiltinOverride is required: "not-found" normalizes to
	// the same key as the built-in bucket this registration shadows.
	pkerrors.RegisterReason("notFound", pkerrors.ReasonSpec{Status: 404, Title: "Not found"}, pkerrors.AllowBuiltinOverride())

	// Public boundary: PublicErrors=true + the attribute-value redaction
	// extension.
	if err := platform.Setup(a.App, platform.Options{
		Config:       a.config.BaseConfiguration,
		Redaction:    RedactionPolicy(),
		PublicErrors: true,
	}); err != nil {
		return err
	}

	// The admin API is unconditional here (this service IS the API; config.go's
	// AdminAPIKey is boot-required, fail closed). A prominent, static startup
	// notice that never logs the key value or its length.
	a.Log().Info("admin API active; X-API-Key required")

	var err error
	a.db, err = pgxpool.New(context.Background(), a.config.PostgresDSN)
	if err != nil {
		return err
	}

	// Client registry bridge (registrydb.Store) — the only external dependency
	// this service has besides POSTGRES_DSN itself. pgxpool.New does not dial
	// eagerly, so constructing it here is safe even against NewTestApp's
	// placeholder POSTGRES_DSN (testing.go); tests swap the store via
	// SetStoreForTest(registrydb.NewFake()) before issuing any real query.
	a.store = registrydb.NewPG(a.db)

	return nil
}

// Config returns the loaded service configuration. Panics if not loaded
// (a handler calling this before New() completes is a bug).
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}
	return a.config
}

// DB returns the Postgres connection pool (registration_api_public role).
func (a *App) DB() *pgxpool.Pool { return a.db }

// Store returns the client registry bridge (registrydb.Store) — init installs
// the production pgx-backed registrydb.PG; SetStoreForTest (testing.go) swaps
// in registrydb.NewFake() for unit tests.
func (a *App) Store() registrydb.Store { return a.store }
