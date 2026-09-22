// Package routes (this file): the admin API's authentication gate.
package routes

import (
	"crypto/subtle"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
)

// requireAPIKey gates the /api group: constant-time-compares the
// X-API-Key header against the configured ADMIN_API_KEY. A missing, empty,
// or wrong key is an indistinguishable 401 (no oracle on WHY it failed —
// fail closed), returning a corehttp.UnauthorizedError{}. The key is never
// logged — this middleware logs nothing at all.
//
// want is captured once per route registration (router.go wires this via
// api.Use(r.requireAPIKey)), and config.go's validate:"required" on
// AdminAPIKey refuses to boot with an empty key, so want == "" can never
// happen in a running service. We check it here too so this middleware fails
// closed on its own.
func (r *router) requireAPIKey(next azugo.RequestHandler) azugo.RequestHandler {
	want := r.Config().AdminAPIKey
	return func(ctx *azugo.Context) {
		got := ctx.Header.Get("X-API-Key")
		if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			ctx.Error(corehttp.UnauthorizedError{})
			return
		}
		next(ctx)
	}
}
