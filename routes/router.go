// Package routes registers eudi-api-registration's HTTP routes: health/readiness
// and the X-API-Key-guarded admin API. Headless machine-to-machine surface
// only — no HTML, no sessions, no CSRF, no operator login. The /api business
// surface (list/create/get/register/transition/webhook) lives in routes/api*.go;
// the key-minting endpoint (POST /clients/{id}/keys) lives in
// routes/api_keys.go. The registrar-identity setter
// (PUT /clients/{id}/registrar-identity, routes/api.go's apiSetRegistrarIdentity)
// wires Store.SetClientRegistrarIdentity.
package routes

import (
	eudiapiregistration "github.com/digimaks/eudi-api-registration"
)

type router struct {
	*eudiapiregistration.App
}

// newRouter builds the router and registers the always-on surface:
// health/readiness plus the admin API group. Split out from Init so tests
// can reuse it without duplicating this wiring.
func newRouter(a *eudiapiregistration.App) (*router, error) {
	r := &router{App: a}

	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)

	// The admin API is always wired here; ADMIN_API_KEY is boot-required
	// (config.go). X-API-Key machine auth (apiauth.go), no sessions, no CSRF
	// anywhere in this service.
	api := a.Group("/api")
	api.Use(r.requireAPIKey)
	api.Get("/clients", r.apiListClients)
	api.Post("/clients", r.apiCreateClient)
	api.Get("/clients/{id}", r.apiGetClient)
	api.Put("/clients/{id}/registrar-identity", r.apiSetRegistrarIdentity)
	api.Put("/clients/{id}/registration", r.apiSetRegistration)
	api.Post("/clients/{id}/transition", r.apiTransition)
	api.Put("/clients/{id}/webhook", r.apiSetWebhook)
	api.Put("/clients/{id}/allowed-origins", r.apiSetAllowedOrigins)
	api.Put("/clients/{id}/dcapi-request-mode", r.apiSetDCAPIRequestMode)
	api.Post("/clients/{id}/keys", r.apiCreateKey)

	return r, nil
}

// Init registers the full route surface.
func Init(a *eudiapiregistration.App) error {
	_, err := newRouter(a)
	return err
}
