// Package routes (this file): the security sweep for this service's mutating
// routes. This service has no HTML, no sessions, and no CSRF wrapper anywhere
// — EVERY mutating (POST/PUT/DELETE) route this service registers sits behind
// the /api group's requireAPIKey (apiauth.go), full stop. Two checks:
//
//  1. TestRouterSourceHasNoUnaccountedMutatingRoute is the "grep that
//     enumerates routes" half: it reads router.go's own source and asserts
//     every POST/PUT/DELETE registration line names a handler
//     apiKeyGuardedRoutePaths (below) already covers — since there is no
//     second, CSRF-guarded table to fall back to here, "unaccounted
//     mutating route" now means exactly "mutating route outside the
//     requireAPIKey-guarded /api group". A future route added to router.go
//     and NOT added here fails this test loudly, rather than silently
//     shipping an unswept (or unguarded) mutating route.
//  2. TestAPIMutatingRoutesRequireAPIKeyNotCSRF proves the guard those
//     routes actually sit behind rejects an unauthenticated request: no
//     X-API-Key (and no session cookie — there is no session concept at all
//     on this machine-to-machine surface) must 401, never a 2xx.
package routes

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"testing"

	corehttp "azugo.io/core/http"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// routerMutatingRouteVerb matches a router.go registration line's verb call
// (`<group>.Post(`, `.Put(`, `.Delete(`; this service has none of the
// latter today) — deliberately tolerant of the receiver name (`a`, `api`
// are both seen in router.go).
var routerMutatingRouteVerb = regexp.MustCompile(`^\s*\w+\.(?:Post|Put|Delete)\(`)

// routerHandlerRef matches every `r.<HandlerName>` reference on a
// registration line — extracting the LAST one handles both the plain form
// (`api.Post("/clients", r.apiCreateClient)`) and any future
// middleware-wrapped form, where the actual handler is the innermost/last
// `r.*` reference on the line, not the first.
var routerHandlerRef = regexp.MustCompile(`\br\.([A-Za-z0-9_]+)\b`)

// TestRouterSourceHasNoUnaccountedMutatingRoute is this sweep's static half
// (the "grep that enumerates routes"): reads router.go's own source and
// asserts every POST/PUT/DELETE registration's handler is one
// apiKeyGuardedRoutePaths (below) already covers — since there is no CSRF
// surface, that table is the SOLE account of legal mutating routes: a
// mutating route is legal iff it is in the /api group guarded by
// requireAPIKey. A future route added to router.go without a matching entry
// here fails this test loudly, rather than silently shipping an unswept
// mutating route.
func TestRouterSourceHasNoUnaccountedMutatingRoute(t *testing.T) {
	f, err := os.Open("router.go")
	qt.Assert(t, qt.IsNil(err))
	defer func() { _ = f.Close() }()

	known := map[string]bool{}
	for _, rt := range apiKeyGuardedRoutePaths {
		known[rt.handler] = true
	}

	found := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if !routerMutatingRouteVerb.MatchString(line) {
			continue
		}
		matches := routerHandlerRef.FindAllStringSubmatch(line, -1)
		qt.Assert(t, qt.IsTrue(len(matches) > 0), qt.Commentf("mutating route registration line named no r.<Handler> reference (update routerHandlerRef or apiKeyGuardedRoutePaths): %q", line))
		handler := "r." + matches[len(matches)-1][1] // the LAST r.* reference on the line is the actual handler
		found[handler] = true
		qt.Check(t, qt.IsTrue(known[handler]),
			qt.Commentf("router.go registers a mutating route for handler %s that apiKeyGuardedRoutePaths (this file) does not cover — every mutating route in this service must sit behind requireAPIKey; add it to the sweep", handler))
	}
	qt.Assert(t, qt.IsNil(sc.Err()))

	// The reverse direction too: every entry in apiKeyGuardedRoutePaths must
	// still correspond to a route router.go actually registers today — a
	// stale entry here (handler renamed/removed) would otherwise silently
	// stop testing anything.
	for handler := range known {
		qt.Check(t, qt.IsTrue(found[handler]),
			qt.Commentf("apiKeyGuardedRoutePaths names handler %s but router.go no longer registers a POST/PUT/DELETE route for it — remove or update this sweep entry", handler))
	}
}

// apiKeyGuardedRoutePaths is every mutating (POST/PUT/DELETE) /api/* route
// router.go registers, WITH ITS HANDLER NAME AND HTTP METHOD. Only GET
// /clients and GET /clients/{id} are non-mutating and so need no entry here.
// The /keys route is POST /clients/{id}/keys, r.apiCreateKey. The
// /registrar-identity route is PUT /clients/{id}/registrar-identity,
// r.apiSetRegistrarIdentity.
//
// method matters here: the routes are not all POST — PUT
// /clients/{id}/registration is a PUT — and sending the WRONG verb to an
// otherwise-registered path is a 405/404 from azugo's own route dispatch
// (method+path are bound together at registration time, route_group.go's
// Handle), which never even reaches requireAPIKey. That would make
// TestAPIMutatingRoutesRequireAPIKeyNotCSRF pass for the wrong reason (or
// fail spuriously), proving nothing about the guard it exists to check.
var apiKeyGuardedRoutePaths = []struct {
	path    string
	method  string
	handler string
}{
	{"/api/clients", fasthttp.MethodPost, "r.apiCreateClient"},
	{"/api/clients/x/registrar-identity", fasthttp.MethodPut, "r.apiSetRegistrarIdentity"},
	{"/api/clients/x/registration", fasthttp.MethodPut, "r.apiSetRegistration"},
	{"/api/clients/x/transition", fasthttp.MethodPost, "r.apiTransition"},
	{"/api/clients/x/webhook", fasthttp.MethodPut, "r.apiSetWebhook"},
	{"/api/clients/x/allowed-origins", fasthttp.MethodPut, "r.apiSetAllowedOrigins"},
	{"/api/clients/x/dcapi-request-mode", fasthttp.MethodPut, "r.apiSetDCAPIRequestMode"},
	{"/api/clients/x/keys", fasthttp.MethodPost, "r.apiCreateKey"},
}

// TestAPIMutatingRoutesRequireAPIKeyNotCSRF is this sweep's dynamic half:
// every route in apiKeyGuardedRoutePaths must reject a request carrying NO
// X-API-Key (and no session cookie either — there is no session concept at
// all on this machine-to-machine surface) with 401 Unauthorized
// (apiauth.go's requireAPIKey returns a corehttp.UnauthorizedError{}), never
// a 403 (there is no CSRF gate to confuse this with) and never a 2xx
// (unguarded).
func TestAPIMutatingRoutesRequireAPIKeyNotCSRF(t *testing.T) {
	// A key IS configured (testAppWithAPI, api_test.go) — this test proves
	// the guard rejects a request that carries none, not that the API is
	// reachable at all.
	app, _, _ := testAppWithAPI(t, "sweep-admin-key")
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	for _, rt := range apiKeyGuardedRoutePaths {
		resp, err := tc.Call(corehttp.Method(rt.method), rt.path, []byte(`{}`))
		qt.Assert(t, qt.IsNil(err), qt.Commentf("%s %s", rt.method, rt.path))
		status := resp.StatusCode()
		fasthttp.ReleaseResponse(resp)
		qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized),
			qt.Commentf("%s %s (handler %s) without X-API-Key must be 401 Unauthorized (the X-API-Key guard), got %d", rt.method, rt.path, rt.handler, status))
	}
}
