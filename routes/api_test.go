package routes

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/argon2"

	eudiapiregistration "github.com/dativa-lv/eudi-api-registration"
	"github.com/dativa-lv/eudi-api-registration/internal/registrydb"
)

// testAppWithAPI boots the app via eudiapiregistration.NewTestApp (testing.go):
// that harness already sets ADMIN_API_KEY=test-admin-key and installs a fresh
// registrydb.Fake before New() ever runs. This wrapper then overrides the
// live Configuration's AdminAPIKey to the caller's own adminKey BEFORE
// wiring the router — apiauth.go's requireAPIKey captures Config().AdminAPIKey
// once, at route-registration time, so the override must land before
// newRouter runs. No session/OIDC setup is needed — there are no sessions
// anywhere in this service.
func testAppWithAPI(t testing.TB, adminKey string) (*azugo.TestApp, *eudiapiregistration.App, *registrydb.Fake) {
	t.Helper()
	app := eudiapiregistration.NewTestApp(t)
	app.Config().AdminAPIKey = adminKey
	fake := registrydb.NewFake()
	app.SetStoreForTest(fake)
	_, err := newRouter(app)
	qt.Assert(t, qt.IsNil(err))
	return azugo.NewTestApp(app.App), app, fake
}

// readBody returns a caller-owned copy of resp's (possibly compressed) body
// and releases resp back to fasthttp's pool.
func readBody(t testing.TB, resp *fasthttp.Response) []byte {
	t.Helper()
	defer fasthttp.ReleaseResponse(resp)
	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	return append([]byte(nil), body...)
}

// problemWire/decodeProblem: the wire shape of pkerrors.Problem this package's
// tests need (just Code, alongside the status already asserted separately).
type problemWire struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code"`
}

func decodeProblem(t testing.TB, body []byte) problemWire {
	t.Helper()
	var p problemWire
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &p)))
	return p
}

// TestAPIListClientsRequiresKey exercises requireAPIKey's no-oracle contract:
// a missing key and a wrong key both fail exactly the same way
// (401, indistinguishable), and only the correct key reaches apiListClients.
func TestAPIListClientsRequiresKey(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	_, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	// no key -> 401
	resp, err := tApp.TestClient().Get("/api/clients")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)

	// wrong key -> 401 (same status as no key at all -- no oracle)
	resp, _ = tApp.TestClient().Get("/api/clients", tApp.TestClient().WithHeader("X-API-Key", "wrong"))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)

	// correct key -> 200 + lists the seeded client
	resp, _ = tApp.TestClient().Get("/api/clients", tApp.TestClient().WithHeader("X-API-Key", "k3y"))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body, _ := resp.BodyUncompressed()
	qt.Assert(t, qt.IsTrue(strings.Contains(string(body), "Acme")))
	fasthttp.ReleaseResponse(resp)
}

// TestAPIListClientsStateFilter exercises apiListClients' ?state= filter
// (?state= uses the raw 7-state names, per the OpenAPI contract's
// listClients): with clients seeded in two DIFFERENT lifecycle states, a
// request scoped to one state returns ONLY that state's client and excludes
// the other. Seeds via CreateDraftClient + the Fake's TestSetClientStatus
// force-set, which deliberately bypasses the legal-transition matrix, since
// this test exercises the FILTER, not the state machine.
func TestAPIListClientsStateFilter(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()

	// Two clients, two distinct states: one left in "draft" (CreateDraftClient's
	// own default), one force-set to "active".
	_, err := fake.CreateDraftClient(t.Context(), "DraftCorp", "", "api")
	qt.Assert(t, qt.IsNil(err))
	activeID, err := fake.CreateDraftClient(t.Context(), "ActiveCorp", "", "api")
	qt.Assert(t, qt.IsNil(err))
	fake.TestSetClientStatus(activeID, "active")

	// ?state=active -> only ActiveCorp, never DraftCorp.
	resp, err := tApp.TestClient().Get("/api/clients?state=active", tApp.TestClient().WithHeader("X-API-Key", "k3y"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body, _ := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	got := string(body)
	qt.Check(t, qt.IsTrue(strings.Contains(got, "ActiveCorp")), qt.Commentf("state=active must include the active client; body=%s", got))
	qt.Check(t, qt.IsFalse(strings.Contains(got, "DraftCorp")), qt.Commentf("state=active must EXCLUDE the draft client; body=%s", got))

	// Sanity: unfiltered lists BOTH, proving the exclusion above is the filter's
	// doing, not a seeding gap.
	resp, err = tApp.TestClient().Get("/api/clients", tApp.TestClient().WithHeader("X-API-Key", "k3y"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body, _ = resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	got = string(body)
	qt.Check(t, qt.IsTrue(strings.Contains(got, "ActiveCorp")), qt.Commentf("unfiltered list must include the active client; body=%s", got))
	qt.Check(t, qt.IsTrue(strings.Contains(got, "DraftCorp")), qt.Commentf("unfiltered list must include the draft client; body=%s", got))
}

// --- POST /clients (create) + GET /clients/{id} (get) ----------------------

// TestAPICreateAndGetClient acceptance: POST /clients creates a draft client
// (201, id/slug minted, state "draft" -- [*] -> Draft), GET /clients/{id}
// reads the SAME client back (name/state round-trip), and a create request
// with no name is rejected as a validation error (400/422) rather than
// silently creating an unnamed client -- the admin API has no wizard step to
// catch this earlier, so apiCreateClient must enforce it itself. Reuses the
// readBody helper rather than defining a second, functionally-identical
// helper.
func TestAPICreateAndGetClient(t *testing.T) {
	tApp, _, _ := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")

	// create
	resp, err := tc.Post("/api/clients", []byte(`{"name":"Acme Demo RP","contactEmail":"ops@acme.test"}`), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	var created apiClientCreated
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &created)))
	qt.Assert(t, qt.Equals(created.State, "draft"))
	qt.Assert(t, qt.IsTrue(created.ID != "" && created.Slug != ""))

	// get
	resp, err = tc.Get("/api/clients/"+created.ID, key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var detail apiClientDetail
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &detail)))
	qt.Assert(t, qt.Equals(detail.State, "draft"))
	qt.Assert(t, qt.Equals(detail.Name, "Acme Demo RP"))
	// The registrar identity is empty until recorded, and both fields are
	// exposed so an operator can see whether the step that records them ran.
	qt.Check(t, qt.Equals(detail.RegistryURI, ""))
	qt.Check(t, qt.Equals(detail.ClientIdentifier, ""))
	resp, err = tc.Put("/api/clients/"+created.ID+"/registrar-identity",
		[]byte(`{"registryUri":"https://registrar.test/api","clientIdentifier":"RP-000123"}`), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNoContent))
	fasthttp.ReleaseResponse(resp)
	resp, err = tc.Get("/api/clients/"+created.ID, key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &detail)))
	qt.Check(t, qt.Equals(detail.RegistryURI, "https://registrar.test/api"))
	qt.Check(t, qt.Equals(detail.ClientIdentifier, "RP-000123"))

	// create with missing name -> 400/422 (validation)
	resp, err = tc.Post("/api/clients", []byte(`{}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(status == fasthttp.StatusBadRequest || status == fasthttp.StatusUnprocessableEntity),
		qt.Commentf("POST /api/clients with no name must be a 400 or 422 validation error, got %d", status))
}

// --- POST /clients/{id}/transition + PUT /clients/{id}/webhook -------------

// TestAPITransition core acceptance: a legal edge (draft ->
// evidence_submitted, registrydb.Fake's legalTransitions) applies and reports
// the ClientState response {id, state} (the OpenAPI contract); a
// SECOND request for an edge that is illegal from the client's now-current
// state (evidence_submitted -> active skips filed_with_registrar/registered
// -- not in legalTransitions) is rejected as err:registry:illegal_transition
// (409), the store's own verdict -- this handler decides neither.
func TestAPITransition(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	// legal edge: draft -> evidence_submitted.
	resp, err := tc.Post("/api/clients/"+id+"/transition", []byte(`{"targetState":"evidence_submitted"}`), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var state apiClientState
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &state)))
	qt.Check(t, qt.Equals(state.ID, id))
	qt.Check(t, qt.Equals(state.State, "evidence_submitted"))

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(full.Status, "evidence_submitted"))

	// illegal edge from the NEW current state: evidence_submitted -> active.
	resp, err = tc.Post("/api/clients/"+id+"/transition", []byte(`{"targetState":"active"}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusConflict))
}

// TestAPITransitionMissingTargetStateIs400 exercises this handler's OWN
// validation (err:api:invalidBody): decode succeeds (valid JSON) but
// targetState is absent, so the handler must reject the request before ever
// calling lifecycle.Service -- a literal path placeholder is enough since no
// Store call is ever reached.
func TestAPITransitionMissingTargetStateIs400(t *testing.T) {
	tApp, _, _ := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")

	resp, err := tc.Post("/api/clients/x/transition", []byte(`{}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
}

// TestAPITransitionActivationRequiresIntendedUse pins the OTHER documented
// response code (the OpenAPI contract's transitionClient '422' entry):
// internal/lifecycle.Service's "-> active" precondition (intended uses
// verified before templates/keys are enabled) runs through the admin API --
// a client walked all the way to "registered" but with ZERO non-revoked
// intended uses (CreateDraftClient seeds none) is rejected as
// err:client:intendedUseRequired (422), and the rejected activation must
// not flip the client's status.
func TestAPITransitionActivationRequiresIntendedUse(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))
	// Registrar identity on file, so the 422 below is the intended-use half.
	fake.TestSetClientRegistrarIdentity(id, "https://registrar.test/api", "RP-000123")

	for _, target := range []string{"evidence_submitted", "filed_with_registrar", "registered"} {
		resp, err := tc.Post("/api/clients/"+id+"/transition", []byte(`{"targetState":"`+target+`"}`), key)
		qt.Assert(t, qt.IsNil(err))
		status := resp.StatusCode()
		fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("-> %s", target))
	}

	resp, err := tc.Post("/api/clients/"+id+"/transition", []byte(`{"targetState":"active"}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(full.Status, "registered"), qt.Commentf("a rejected activation must not flip status"))
}

// TestAPISetWebhook core acceptance: a valid absolute-https URL is persisted
// (registry.client.default_webhook_url via registrydb.Store.SetClientWebhook)
// and the 200 response is apiClientWebhookState {id, state, webhookUrl} --
// the ClientWebhookState shape (ClientState PLUS webhookUrl), NOT a bare
// {id, webhookUrl} echo (see apiClientWebhookState's doc comment).
func TestAPISetWebhook(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	resp, err := tc.Put("/api/clients/"+id+"/webhook", []byte(`{"webhookUrl":"https://acme.test/wh"}`), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var state apiClientWebhookState
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &state)))
	qt.Check(t, qt.Equals(state.ID, id))
	qt.Check(t, qt.Equals(state.State, "draft"))
	qt.Check(t, qt.Equals(state.WebhookURL, "https://acme.test/wh"))

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(full.DefaultWebhook, "https://acme.test/wh"))
}

// TestAPISetWebhookRejectsNonHTTPS: registrydb.Store.SetClientWebhook's own
// validation (a non-absolute-https URL is err:registry:invalid) is surfaced
// verbatim as 400 -- this handler validates nothing about the URL's shape
// itself.
func TestAPISetWebhookRejectsNonHTTPS(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	resp, err := tc.Put("/api/clients/"+id+"/webhook", []byte(`{"webhookUrl":"/relative/path"}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(full.DefaultWebhook, ""))
}

// TestAPISetWebhookMissingURLIs400 exercises this handler's OWN validation
// (err:api:invalidBody) for a body with no webhookUrl at all. A status-only
// assertion would NOT discriminate here: an empty URL also trips the store's
// own empty-check (registrydb.Fake.SetClientWebhook rejects webhookURL == ""
// with err:registry:invalid), which is ALSO a 400 -- so if a future refactor
// dropped the handler's req.WebhookURL == "" guard, callers would silently
// get the generic err:registry:invalid instead of the precise
// err:api:invalidBody and a status-only test would keep passing. The body
// assertion on the exact code is what pins that THIS handler's guard fired,
// not the store fallthrough.
func TestAPISetWebhookMissingURLIs400(t *testing.T) {
	tApp, _, _ := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")

	resp, err := tc.Put("/api/clients/x/webhook", []byte(`{}`), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	qt.Check(t, qt.StringContains(string(readBody(t, resp)), `"code":"err:api:invalidBody"`))
}

// --- PUT /clients/{id}/registrar-identity -----------------------------------

// TestAPISetRegistrarIdentity core acceptance: a valid absolute-https
// registryUri + non-empty clientIdentifier persist via
// Store.SetClientRegistrarIdentity, and the response is 204 No Content --
// there is nothing to echo back, and this endpoint never itself changes
// lifecycle state (same reasoning as apiSetRegistration's own doc comment).
func TestAPISetRegistrarIdentity(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	resp, err := tc.Put("/api/clients/"+id+"/registrar-identity",
		[]byte(`{"registryUri":"https://registrar.example.lv/ts5","clientIdentifier":"LV-RP-000123"}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusNoContent))

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(full.RegistryURI, "https://registrar.example.lv/ts5"))
	qt.Check(t, qt.Equals(full.ClientIdentifier, "LV-RP-000123"))
}

// TestAPISetRegistrarIdentityMalformedJSONIs400 exercises the same
// err:api:invalidBody path every other admin-API mutation uses for a body
// that isn't valid JSON at all -- decode fails before any Store call ever
// runs, so an unknown client id would not change this outcome.
func TestAPISetRegistrarIdentityMalformedJSONIs400(t *testing.T) {
	tApp, _, _ := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")

	resp, err := tc.Put("/api/clients/x/registrar-identity", []byte(`not json`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
}

// TestAPISetRegistrarIdentityInvalidRegistryURIIs400 pins this handler's OWN
// https-shape validation (isAbsoluteHTTPSURL, api.go): neither
// registry.set_client_registrar_identity nor registrydb.Fake's own
// SetClientRegistrarIdentity validate registryUri's shape (only
// non-emptiness) -- unlike SetClientWebhook's own defense-in-depth check --
// so without this handler's own guard, a non-https or relative value would
// otherwise persist silently. Covers both a non-https scheme and a relative
// reference, and confirms the rejected value never reached the store.
func TestAPISetRegistrarIdentityInvalidRegistryURIIs400(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")

	for _, badURI := range []string{"http://registrar.example.lv/ts5", "/relative/ts5"} {
		id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
		qt.Assert(t, qt.IsNil(err))

		resp, err := tc.Put("/api/clients/"+id+"/registrar-identity",
			[]byte(`{"registryUri":"`+badURI+`","clientIdentifier":"LV-RP-000123"}`), key)
		qt.Assert(t, qt.IsNil(err))
		status := resp.StatusCode()
		fasthttp.ReleaseResponse(resp)
		qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("registryUri=%q", badURI))

		full, err := fake.GetClientFull(t.Context(), id)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(full.RegistryURI, ""), qt.Commentf("rejected registryUri=%q must not persist", badURI))
	}
}

// TestAPISetRegistrarIdentityEmptyClientIdentifierIs400 exercises the other
// half of this handler's own required-fields check (an otherwise-valid
// absolute-https registryUri, but an empty clientIdentifier).
func TestAPISetRegistrarIdentityEmptyClientIdentifierIs400(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	resp, err := tc.Put("/api/clients/"+id+"/registrar-identity",
		[]byte(`{"registryUri":"https://registrar.example.lv/ts5","clientIdentifier":""}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
}

// TestAPISetRegistrarIdentityEmptyRegistryURIIs400 exercises the OTHER
// (previously untested) branch of the same OR'd required-fields check --
// an empty registryUri paired with a NON-empty clientIdentifier -- mirroring
// TestAPISetRegistrarIdentityEmptyClientIdentifierIs400 above but for the
// other operand, and additionally confirms neither value persists.
func TestAPISetRegistrarIdentityEmptyRegistryURIIs400(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	resp, err := tc.Put("/api/clients/"+id+"/registrar-identity",
		[]byte(`{"registryUri":"","clientIdentifier":"LV-RP-000123"}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(full.RegistryURI, ""), qt.Commentf("empty registryUri must not persist"))
	qt.Check(t, qt.Equals(full.ClientIdentifier, ""), qt.Commentf("clientIdentifier must not persist when registryUri was rejected"))
}

// TestAPISetRegistrarIdentityUnknownClientIs404 pins the store's own
// err:registry:not_found (404, underscore -- the raw reason registry.*
// procedures raise, see registrydb doc comments), surfaced verbatim -- this
// handler decides neither this nor any other Store outcome (same convention
// as apiCreateKey/apiSetWebhook against an unknown id). The domain-specific
// code (rather than a generic err:request:notFound) comes from the
// AllowBuiltinOverride registration in app.go's init.
func TestAPISetRegistrarIdentityUnknownClientIs404(t *testing.T) {
	tApp, _, _ := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")

	resp, err := tc.Put("/api/clients/no-such-client/registrar-identity",
		[]byte(`{"registryUri":"https://registrar.example.lv/ts5","clientIdentifier":"LV-RP-000123"}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	body := readBody(t, resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusNotFound))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:registry:not_found"))
}

// --- POST /clients/{id}/keys ------------------------------------------------

// verifyPHC parses a $argon2id$v=19$m=19456,t=2,p=1$<salt>$<tag> PHC string
// (base64.RawStdEncoding halves) and reports whether secret hashes to the
// stored tag under those exact params — an independent, from-scratch
// recompute (never calling into internal/apikeys' own code), so this test
// helper cannot share a bug with the implementation it is checking.
func verifyPHC(t testing.TB, phcHash, secret string) bool {
	t.Helper()
	parts := strings.Split(phcHash, "$")
	qt.Assert(t, qt.Equals(len(parts), 6), qt.Commentf("malformed PHC hash: %q", phcHash))
	qt.Assert(t, qt.Equals(parts[1], "argon2id"))
	qt.Assert(t, qt.Equals(parts[3], "m=19456,t=2,p=1"))

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	qt.Assert(t, qt.IsNil(err))
	tag, err := base64.RawStdEncoding.DecodeString(parts[5])
	qt.Assert(t, qt.IsNil(err))

	got := argon2.IDKey([]byte(secret), salt, 2, 19456, 1, 32)
	return subtle.ConstantTimeCompare(got, tag) == 1
}

// TestAPICreateKeyRequiresKey: POST /api/clients/{id}/keys without X-API-Key
// is 401 -- same no-oracle body as every other guarded route (apiauth.go's
// requireAPIKey never distinguishes "missing key" from any other reason).
func TestAPICreateKeyRequiresKey(t *testing.T) {
	tApp, _, _ := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()

	resp, err := tApp.TestClient().Post("/api/clients/some-id/keys", nil)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized))
}

// TestAPICreateKeyUnknownClient404: an unknown id surfaces GetClientFull's
// own err:registry:not_found (404) BEFORE any key material is generated --
// apiCreateKey (routes/api_keys.go) calls GetClientFull first, so no
// apikeys.Mint/Store.CreateAPIKey call ever happens for an unknown client.
func TestAPICreateKeyUnknownClient404(t *testing.T) {
	tApp, _, _ := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")

	resp, err := tc.Post("/api/clients/no-such-client/keys", nil, key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusNotFound))
}

// TestAPICreateKeyMintsVerifiableKey core acceptance: 201; the response shape
// is the OpenAPI contract's ApiKeyCreated {clientId, prefix, apiKey}; the
// Fake-stored row's argon2id PHC hash verifies against the returned secret
// (recomputed from scratch by verifyPHC), and prefix is consistent between
// the display key, the response field, and the stored row -- proving the
// handler never stores the display key itself, only its hash.
func TestAPICreateKeyMintsVerifiableKey(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")

	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	resp, err := tc.Post("/api/clients/"+id+"/keys", nil, key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var out apiKeyCreated
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &out)))
	qt.Check(t, qt.Equals(out.ClientID, id))
	qt.Assert(t, qt.IsTrue(out.Prefix != ""))
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(out.APIKey, "vk_"+out.Prefix+"_")))

	rows := fake.APIKeys(id)
	qt.Assert(t, qt.Equals(len(rows), 1))
	qt.Check(t, qt.Equals(rows[0].Prefix, out.Prefix))
	secret := strings.TrimPrefix(out.APIKey, "vk_"+out.Prefix+"_")
	qt.Check(t, qt.IsTrue(verifyPHC(t, rows[0].SecretHash, secret)))
}

// TestAPISetAllowedOrigins: the setter that makes the browser-mediated
// presentation flow reachable at all. Before it existed the column could only
// be written at client creation, so no real client ever had an origin.
func TestAPISetAllowedOrigins(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	body := []byte(`{"allowedOrigins":["https://acme.test","https://acme.test:19090"]}`)
	resp, err := tc.Put("/api/clients/"+id+"/allowed-origins", body, key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var state apiClientOriginsState
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &state)))
	qt.Check(t, qt.Equals(state.ID, id))
	qt.Check(t, qt.Equals(state.State, "draft"))
	qt.Check(t, qt.DeepEquals(state.AllowedOrigins, []string{"https://acme.test", "https://acme.test:19090"}))

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(full.AllowedOrigins, []string{"https://acme.test", "https://acme.test:19090"}))
}

// TestAPISetAllowedOriginsReplacesNotAppends: the list is a whitelist, so a
// second call must REPLACE it. An append-only setter would leave no way to
// withdraw an origin that should no longer be trusted.
func TestAPISetAllowedOriginsReplacesNotAppends(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	for _, b := range []string{
		`{"allowedOrigins":["https://first.test","https://second.test"]}`,
		`{"allowedOrigins":["https://third.test"]}`,
	} {
		resp, err := tc.Put("/api/clients/"+id+"/allowed-origins", []byte(b), key)
		qt.Assert(t, qt.IsNil(err))
		status := resp.StatusCode()
		fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	}

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(full.AllowedOrigins, []string{"https://third.test"}))
}

// TestAPISetAllowedOriginsEmptyWithdraws: an empty array is a deliberate act
// (withdraw every origin), while an ABSENT key is a malformed request. The two
// must not be confused, or a caller who forgot the field would silently strip
// a client's origins.
func TestAPISetAllowedOriginsEmptyWithdraws(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	resp, err := tc.Put("/api/clients/"+id+"/allowed-origins", []byte(`{"allowedOrigins":["https://acme.test"]}`), key)
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.Put("/api/clients/"+id+"/allowed-origins", []byte(`{"allowedOrigins":[]}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(full.AllowedOrigins), 0))

	// Omitted key: rejected, and the stored list is left alone.
	resp, err = tc.Put("/api/clients/"+id+"/allowed-origins", []byte(`{}`), key)
	qt.Assert(t, qt.IsNil(err))
	status = resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
}

// TestAPISetAllowedOriginsRejectsNonOrigins pins the shape at the boundary:
// each of these would be stored happily by a looser check and then never match
// a real browser origin, which is compared literally.
func TestAPISetAllowedOriginsRejectsNonOrigins(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	for _, origin := range []string{
		"http://acme.test", "https://", "https://acme.test/", "https://acme.test/p",
		"https://acme.test?q=1", "https://acme.test#f", "https://u@acme.test",
		"acme.test", "",
	} {
		t.Run(origin, func(t *testing.T) {
			body := []byte(`{"allowedOrigins":["https://good.test",` + mustQuote(origin) + `]}`)
			resp, err := tc.Put("/api/clients/"+id+"/allowed-origins", body, key)
			qt.Assert(t, qt.IsNil(err))
			status := resp.StatusCode()
			fasthttp.ReleaseResponse(resp)
			qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
		})
	}

	// Nothing was stored by any of the rejected calls — a partial write would
	// be worse than a rejection.
	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(full.AllowedOrigins), 0))
}

// TestAPISetDCAPIRequestMode: the per-client choice round-trips, is echoed
// back read from stored state rather than from the request, and is recorded
// even when it matches the default — "deliberately signed" and "never decided"
// have to stay distinguishable in the stored policy.
func TestAPISetDCAPIRequestMode(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	// A client nobody has decided about reads as signed.
	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(storedDCAPIMode(full.Policy), "signed"))

	resp, err := tc.Put("/api/clients/"+id+"/dcapi-request-mode", []byte(`{"dcapiRequestMode":"unsigned"}`), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var state apiClientDCAPIModeState
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &state)))
	qt.Check(t, qt.Equals(state.ID, id))
	qt.Check(t, qt.Equals(state.State, "draft"))
	qt.Check(t, qt.Equals(state.Mode, "unsigned"))

	full, err = fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(storedDCAPIMode(full.Policy), "unsigned"))

	// Back to signed: recorded explicitly, not by dropping the flag.
	resp, err = tc.Put("/api/clients/"+id+"/dcapi-request-mode", []byte(`{"dcapiRequestMode":"signed"}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	full, err = fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(string(full.Policy), "require_signed_dcapi")))
	qt.Check(t, qt.Equals(storedDCAPIMode(full.Policy), "signed"))
}

// TestAPISetDCAPIRequestModeMergesPolicy: the write must not disturb the other
// verification choices stored in the same document. Silently resetting them
// would relax a client's verification as a side effect of an unrelated call.
func TestAPISetDCAPIRequestModeMergesPolicy(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))
	fake.TestSetClientPolicy(id, []byte(`{"revocation_fail_closed":false}`))

	resp, err := tc.Put("/api/clients/"+id+"/dcapi-request-mode", []byte(`{"dcapiRequestMode":"unsigned"}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(string(full.Policy), "revocation_fail_closed")))
	qt.Check(t, qt.Equals(storedDCAPIMode(full.Policy), "unsigned"))
}

// TestAPISetDCAPIRequestModeRejects: neither an absent field nor an invented
// mode may be guessed at — both modes are meaningful, so there is no safe
// default to fall back to, and nothing may be stored by a rejected call.
func TestAPISetDCAPIRequestModeRejects(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	for _, body := range []string{
		`{}`, `{"dcapiRequestMode":""}`, `{"dcapiRequestMode":"both"}`,
		`{"dcapiRequestMode":"Signed"}`, `{"dcapiRequestMode":"none"}`, `not json`,
	} {
		t.Run(body, func(t *testing.T) {
			resp, err := tc.Put("/api/clients/"+id+"/dcapi-request-mode", []byte(body), key)
			qt.Assert(t, qt.IsNil(err))
			status := resp.StatusCode()
			fasthttp.ReleaseResponse(resp)
			qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
		})
	}

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(storedDCAPIMode(full.Policy), "signed"))

	// An unknown client is the store's 404, not this handler's 400.
	resp, err := tc.Put("/api/clients/no-such-client/dcapi-request-mode",
		[]byte(`{"dcapiRequestMode":"signed"}`), key)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(status, fasthttp.StatusNotFound))
}

func mustQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestAPITransitionActivationRequiresRegistrarIdentity pins the other
// activation precondition through the admin API: a client walked to
// "registered" with a registration document (so an intended use exists) but
// WITHOUT ever calling PUT /clients/{id}/registrar-identity is refused with
// err:client:registrarIdentityRequired (422), the detail names that call, and
// the rejected activation does not flip the status.
func TestAPITransitionActivationRequiresRegistrarIdentity(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(fake.SaveWRPDocument(t.Context(), id, json.RawMessage(`{}`),
		[]registrydb.IntendedUse{{IntendedUseID: "iu-1"}}, "api")))

	for _, target := range []string{"evidence_submitted", "filed_with_registrar", "registered"} {
		resp, err := tc.Post("/api/clients/"+id+"/transition", []byte(`{"targetState":"`+target+`"}`), key)
		qt.Assert(t, qt.IsNil(err))
		status := resp.StatusCode()
		fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("-> %s", target))
	}

	resp, err := tc.Post("/api/clients/"+id+"/transition", []byte(`{"targetState":"active"}`), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &problem)))
	qt.Check(t, qt.Equals(problem.Code, "err:client:registrarIdentityRequired"))
	qt.Check(t, qt.StringContains(problem.Detail, "PUT /api/clients/{id}/registrar-identity"))

	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(full.Status, "registered"), qt.Commentf("a rejected activation must not flip status"))
}
