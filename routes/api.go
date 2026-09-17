// Package routes (this file): the operator-scoped admin API (/api/*,
// registered unconditionally — this service IS the API). Guarded by
// requireAPIKey (apiauth.go), NOT a browser session: this is
// machine-to-machine X-API-Key auth, so it carries no CSRF wrapper. This file
// holds the list, create, get, transition and webhook endpoints plus
// apiSetRegistrarIdentity; structured registration lives in its own file
// (api_registration.go) for its larger DTO surface.
package routes

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/dativa-lv/eudi-api-registration/internal/lifecycle"
)

// apiClientSummary is the admin API's wire DTO for one client, matching the
// OpenAPI contract's ClientSummary schema field for field (camelCase, "state"
// not registrydb.ClientSummary's "status") — a deliberate contract type kept
// separate from registrydb.ClientSummary so the wire shape can evolve
// independently of the storage projection.
type apiClientSummary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug,omitempty"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// apiListClients handles GET /api/clients (the OpenAPI contract's
// listClients): optional ?state= filters to one lifecycle state (the raw
// 7-state names); otherwise every client, flattened across states.
func (r *router) apiListClients(ctx *azugo.Context) {
	byState, err := r.Store().ListClientsByState(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}

	want := ctx.Query.StringOptional("state")
	out := make([]apiClientSummary, 0)
	for state, cs := range byState {
		if want != nil && state != *want {
			continue
		}
		for _, c := range cs {
			out = append(out, apiClientSummary{
				ID:        c.ID,
				Name:      c.Name,
				Slug:      c.Slug,
				State:     c.Status,
				UpdatedAt: c.UpdatedAt,
			})
		}
	}
	ctx.JSON(out)
}

// apiCreateRequest is the wire body for POST /api/clients (the OpenAPI
// contract's CreateClientRequest): name is required (enforced by
// apiCreateClient itself); contactEmail is optional.
type apiCreateRequest struct {
	Name         string `json:"name"`
	ContactEmail string `json:"contactEmail,omitempty"`
}

// apiClientCreated is the 201 response for POST /api/clients (the OpenAPI
// contract's ClientCreated): a freshly created client always starts in
// "draft".
type apiClientCreated struct {
	ID    string `json:"id"`
	Slug  string `json:"slug"`
	State string `json:"state"`
}

// apiClientDetail is the response for GET /api/clients/{id} (the OpenAPI
// contract's ClientDetail). Deliberately carries NO createdAt/updatedAt
// fields — neither is backed by registrydb.ClientFull/GetClientFull, and we
// do not add a new DB procedure just to project them. Slug is omitempty per
// the contract (absent for a client created before slugs existed) — every
// OTHER field here is always present, matching the schema's `required` list.
type apiClientDetail struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Slug       string `json:"slug,omitempty"`
	State      string `json:"state"`
	WebhookURL string `json:"webhookUrl"`
	// RegistryURI / ClientIdentifier are the registrar identity recorded with
	// PUT /api/clients/{id}/registrar-identity — empty strings until it is.
	// Exposed so the one onboarding step that lives outside the registration
	// document and the lifecycle transitions is visible, instead of write-only:
	// activation refuses without it, and a client activated before that rule
	// fails at its first session without it.
	RegistryURI      string          `json:"registryUri"`
	ClientIdentifier string          `json:"clientIdentifier"`
	Registration     json.RawMessage `json:"registration"` // stored ARF TS5 doc, or null
}

// apiCreateClient handles POST /api/clients (the OpenAPI contract's
// createClient): create a draft client from a bare name + optional contact
// email — no evidence step, matching this surface's headless intent. A
// malformed body or a missing/empty name is rejected as err:api:invalidBody
// (400): the ONE validation this handler does itself, since CreateDraftClient
// takes name as a bare string with no not-empty constraint of its own
// (registry.create_draft_client has no such check) — so the handler is the
// only place it is enforced.
func (r *router) apiCreateClient(ctx *azugo.Context) {
	var req apiCreateRequest
	if err := json.Unmarshal(ctx.Request().Body(), &req); err != nil {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("body is not valid JSON")))
		return
	}
	if req.Name == "" {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("name is required")))
		return
	}

	id, err := r.Store().CreateDraftClient(ctx, req.Name, req.ContactEmail, "api")
	if err != nil {
		ctx.Error(err)
		return
	}
	full, err := r.Store().GetClientFull(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(apiClientCreated{ID: full.ID, Slug: full.Slug, State: full.Status})
}

// apiGetClient handles GET /api/clients/{id} (the OpenAPI contract's
// getClient): the client's full detail, including its stored registration
// document (or null if none has been submitted yet — ClientFull.WRPDocument's
// own doc comment). An unknown id surfaces GetClientFull's own
// err:registry:not_found (404) verbatim — this handler never distinguishes
// "unknown id" from any other Store failure.
func (r *router) apiGetClient(ctx *azugo.Context) {
	full, err := r.Store().GetClientFull(ctx, ctx.Params.String("id"))
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(apiClientDetail{
		ID:               full.ID,
		Name:             full.Name,
		Slug:             full.Slug,
		State:            full.Status,
		WebhookURL:       full.DefaultWebhook,
		RegistryURI:      full.RegistryURI,
		ClientIdentifier: full.ClientIdentifier,
		Registration:     full.WRPDocument,
	})
}

// apiTransitionRequest is POST /api/clients/{id}/transition's wire body (the
// OpenAPI contract's TransitionRequest): targetState is the only required
// field (one of ClientLifecycleState's 7 state names); reason and evidenceRef
// are optional and forwarded as-is to lifecycle.Service.Transition, which
// audits them alongside the transition — this handler validates neither
// beyond "targetState is non-empty".
type apiTransitionRequest struct {
	TargetState string `json:"targetState"`
	Reason      string `json:"reason,omitempty"`
	EvidenceRef string `json:"evidenceRef,omitempty"`
}

// apiClientState is the 200 response for POST /api/clients/{id}/transition
// (the OpenAPI contract's ClientState): the client id echoed back
// plus its new state. Built directly from the request's own targetState
// rather than a fresh GetClientFull — lifecycle.Service.Transition returning
// nil already guarantees the client's current status IS targetState (every
// success path either flips the client to toState via Store.TransitionClient,
// or — for the already-offboarded retry case, its own doc comment — leaves
// it at an offboarded status that already equals toState), so a second read
// would be redundant.
type apiClientState struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// apiWebhookRequest is PUT /api/clients/{id}/webhook's wire body (the OpenAPI
// contract's WebhookRequest): webhookUrl is required; Store.SetClientWebhook
// (not this handler) validates it is an absolute https URL.
type apiWebhookRequest struct {
	WebhookURL string `json:"webhookUrl"`
}

// apiClientWebhookState is the 200 response for PUT /api/clients/{id}/webhook
// (the OpenAPI contract's ClientWebhookState — ClientState's {id, state} PLUS
// webhookUrl, deliberately not a bare {id, webhookUrl} echo). State is read
// back via GetClientFull AFTER the write, since — unlike apiClientState above
// — nothing about this request tells us the client's CURRENT lifecycle state;
// this endpoint never itself changes it.
type apiClientWebhookState struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	WebhookURL string `json:"webhookUrl"`
}

// apiTransition handles POST /api/clients/{id}/transition (the OpenAPI
// contract's transitionClient): drives one client-lifecycle edge via
// lifecycle.Service, actor "api" — there is no operator session on this
// machine-to-machine surface (same fixed-actor convention
// apiCreateClient/apiSetRegistration already use). A missing targetState is
// err:api:invalidBody (400); an illegal edge is the store's own
// err:registry:illegal_transition (409); a "-> active" request without a
// non-revoked intended use is err:client:intendedUseRequired (422) — all
// three surfaced verbatim, this handler decides none of them
// (lifecycle.Service's own package doc comment).
func (r *router) apiTransition(ctx *azugo.Context) {
	var req apiTransitionRequest
	if err := json.Unmarshal(ctx.Request().Body(), &req); err != nil {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("body is not valid JSON")))
		return
	}
	if req.TargetState == "" {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("targetState is required")))
		return
	}

	id := ctx.Params.String("id")
	svc := lifecycle.NewService(r.Store())
	if err := svc.Transition(ctx, id, req.TargetState, "api", req.EvidenceRef, req.Reason); err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(apiClientState{ID: id, State: req.TargetState})
}

// apiSetWebhook handles PUT /api/clients/{id}/webhook (the OpenAPI contract's
// setClientWebhook): sets registry.client.default_webhook_url through
// Store.SetClientWebhook, actor "api" (same convention as apiTransition
// above). A missing webhookUrl is err:api:invalidBody (400); a malformed
// (non-absolute-https) value is the store's own err:registry:invalid (400);
// an unknown id is err:registry:not_found (404) — all surfaced verbatim. See
// apiClientWebhookState's doc comment for why State is read back via
// GetClientFull rather than assumed.
func (r *router) apiSetWebhook(ctx *azugo.Context) {
	var req apiWebhookRequest
	if err := json.Unmarshal(ctx.Request().Body(), &req); err != nil {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("body is not valid JSON")))
		return
	}
	if req.WebhookURL == "" {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("webhookUrl is required")))
		return
	}

	id := ctx.Params.String("id")
	if err := r.Store().SetClientWebhook(ctx, id, req.WebhookURL, "api"); err != nil {
		ctx.Error(err)
		return
	}

	full, err := r.Store().GetClientFull(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(apiClientWebhookState{ID: id, State: full.Status, WebhookURL: full.DefaultWebhook})
}

// apiAllowedOriginsRequest is PUT /api/clients/{id}/allowed-origins' wire
// body. allowedOrigins is required but MAY be empty: replacing the list with
// none is how an origin is withdrawn, and that has to be distinguishable from
// omitting the field by mistake — so a missing key is rejected while an empty
// array is honoured.
type apiAllowedOriginsRequest struct {
	AllowedOrigins *[]string `json:"allowedOrigins"`
}

// apiClientOriginsState echoes what is now stored, read back through
// GetClientFull for the same reason apiClientWebhookState does rather than
// assuming the write took the value verbatim.
type apiClientOriginsState struct {
	ID             string   `json:"id"`
	State          string   `json:"state"`
	AllowedOrigins []string `json:"allowedOrigins"`
}

// isWebOrigin reports whether raw is a bare web origin: https, a host, and
// nothing else. url.Parse alone accepts far more than that, so Scheme/Host and
// the absence of every other component are checked explicitly — the same
// "this handler does its own one validation" convention apiCreateClient's name
// check and apiSetRegistrarIdentity's URL check already use.
//
// The comparison performed against a caller's real origin later is literal, so
// a near-miss accepted here (a trailing slash, a path) would be stored happily
// and then never match anything. Rejecting it at configuration time is the
// whole point.
//
// NOTE: the presentation engine and the session service enforce this same rule
// independently. Three statements of one rule is two too many; consolidating
// them onto a single exported helper is tracked in the workspace backlog.
func isWebOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != "" && u.Path == "" &&
		u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// apiSetAllowedOrigins handles PUT /api/clients/{id}/allowed-origins: sets
// registry.client.allowed_origins through Store.SetClientAllowedOrigins, actor
// "api" (same fixed-actor convention as the setters above). A missing
// allowedOrigins key or a malformed entry is err:api:invalidBody (400, this
// handler's own check — see isWebOrigin); the store's own
// err:registry:invalid (400) and err:registry:not_found (404) surface
// verbatim. The offending value is echoed back because an operator fixing a
// mistyped origin needs to see which one was wrong, and an origin they just
// sent us is not a secret.
func (r *router) apiSetAllowedOrigins(ctx *azugo.Context) {
	var req apiAllowedOriginsRequest
	if err := json.Unmarshal(ctx.Request().Body(), &req); err != nil {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("body is not valid JSON")))
		return
	}
	if req.AllowedOrigins == nil {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody",
			pkerrors.WithPublicDetail("allowedOrigins is required (send an empty array to withdraw every origin)")))
		return
	}
	for _, o := range *req.AllowedOrigins {
		if !isWebOrigin(o) {
			ctx.Error(pkerrors.NewProblem("err:api:invalidBody",
				pkerrors.WithPublicDetail(fmt.Sprintf(
					"allowedOrigins[%q] must be https://host[:port] with no path, query, fragment or userinfo", o))))
			return
		}
	}

	id := ctx.Params.String("id")
	if err := r.Store().SetClientAllowedOrigins(ctx, id, *req.AllowedOrigins, "api"); err != nil {
		ctx.Error(err)
		return
	}

	full, err := r.Store().GetClientFull(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(apiClientOriginsState{ID: id, State: full.Status, AllowedOrigins: full.AllowedOrigins})
}

// apiDCAPIModeRequest is PUT /api/clients/{id}/dcapi-request-mode's wire body.
// A pointer for the same reason apiAllowedOriginsRequest uses one: an omitted
// field must be rejected outright rather than read as one of the two modes,
// because both of them are meaningful and neither is a safe guess.
type apiDCAPIModeRequest struct {
	Mode *string `json:"dcapiRequestMode"`
}

// apiClientDCAPIModeState echoes what is now stored, read back through
// GetClientFull for the same reason apiClientWebhookState does.
type apiClientDCAPIModeState struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Mode  string `json:"dcapiRequestMode"`
}

// storedDCAPIMode reports the mode a stored policy document expresses.
// The flag is optional and its ABSENCE means signed: a client nobody has
// decided about gets the mode that lets the wallet authenticate us, never the
// one that does not. Unreadable policy JSON reads as signed for the same
// reason — a corrupt document must not silently relax anything.
func storedDCAPIMode(policy json.RawMessage) string {
	var p struct {
		RequireSigned *bool `json:"require_signed_dcapi"`
	}
	if len(policy) > 0 {
		if err := json.Unmarshal(policy, &p); err != nil {
			return "signed"
		}
	}
	if p.RequireSigned != nil && !*p.RequireSigned {
		return "unsigned"
	}
	return "signed"
}

// apiSetDCAPIRequestMode handles PUT /api/clients/{id}/dcapi-request-mode:
// chooses signed or unsigned browser-based presentation requests for one
// client through Store.SetClientDCAPIMode, actor "api" (same fixed-actor
// convention as the setters above).
//
// This is a per-client choice WITHIN what the deployment already permits — a
// deployment restricted to signed requests keeps issuing signed ones for a
// client recorded as unsigned, so this endpoint can never widen a deployment,
// only narrow a client inside it. That is why an unsigned choice is accepted
// here without knowing how the presentation service is configured.
//
// A missing or unknown mode is err:api:invalidBody (400, this handler's own
// check); the store's err:registry:not_found (404) surfaces verbatim. The
// rejected value is echoed back because an operator who mistyped a mode needs
// to see which word was wrong.
func (r *router) apiSetDCAPIRequestMode(ctx *azugo.Context) {
	var req apiDCAPIModeRequest
	if err := json.Unmarshal(ctx.Request().Body(), &req); err != nil {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("body is not valid JSON")))
		return
	}
	if req.Mode == nil {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody",
			pkerrors.WithPublicDetail(`dcapiRequestMode is required ("signed" or "unsigned")`)))
		return
	}
	if *req.Mode != "signed" && *req.Mode != "unsigned" {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody",
			pkerrors.WithPublicDetail(fmt.Sprintf(
				"dcapiRequestMode %q must be \"signed\" or \"unsigned\"", *req.Mode))))
		return
	}

	id := ctx.Params.String("id")
	if err := r.Store().SetClientDCAPIMode(ctx, id, *req.Mode, "api"); err != nil {
		ctx.Error(err)
		return
	}

	full, err := r.Store().GetClientFull(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(apiClientDCAPIModeState{ID: id, State: full.Status, Mode: storedDCAPIMode(full.Policy)})
}

// apiRegistrarIdentityRequest is PUT /api/clients/{id}/registrar-identity's
// wire body (the OpenAPI contract's RegistrarIdentityRequest): both fields
// are required. registry.set_client_registrar_identity (and registrydb.Fake's
// own SetClientRegistrarIdentity) only reject EMPTY values — neither validates
// registryUri's shape — so the "must be an absolute https URL" check is this
// handler's OWN validation, the same "one validation the handler does itself"
// convention apiCreateClient's name check and apiTransition's targetState
// check already use, since the layer underneath has no such constraint of its
// own to lean on.
type apiRegistrarIdentityRequest struct {
	RegistryURI      string `json:"registryUri"`
	ClientIdentifier string `json:"clientIdentifier"`
}

// isAbsoluteHTTPSURL mirrors internal/wizard's validateHTTPSPolicyURI idiom:
// url.Parse alone accepts relative references and non-http(s) schemes
// without error, so Scheme/Host are checked explicitly.
func isAbsoluteHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// apiSetRegistrarIdentity handles PUT /api/clients/{id}/registrar-identity
// (the OpenAPI contract's setClientRegistrarIdentity): sets
// registry.client.registry_uri/client_identifier through
// Store.SetClientRegistrarIdentity, actor "api" (same fixed-actor convention
// apiTransition/apiSetWebhook already use — there is no operator session on
// this machine-to-machine surface). A missing/empty registryUri or
// clientIdentifier is err:api:invalidBody (400, this handler's own check,
// mirroring the underlying procedure's own combined "required" error
// message); a non-absolute-https registryUri is ALSO err:api:invalidBody
// (400) — see apiRegistrarIdentityRequest's doc comment for why this handler
// checks that shape itself rather than delegating to the Store. An unknown
// client id surfaces the store's own err:registry:not_found (404) verbatim.
// Success is 204 No Content: the request body already states exactly what
// was set, and — like apiSetRegistration's own description — this endpoint
// never itself changes lifecycle state, so there is nothing else to report.
func (r *router) apiSetRegistrarIdentity(ctx *azugo.Context) {
	var req apiRegistrarIdentityRequest
	if err := json.Unmarshal(ctx.Request().Body(), &req); err != nil {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("body is not valid JSON")))
		return
	}
	if req.RegistryURI == "" || req.ClientIdentifier == "" {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("registryUri and clientIdentifier are required")))
		return
	}
	if !isAbsoluteHTTPSURL(req.RegistryURI) {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("registryUri must be an absolute https URL")))
		return
	}

	id := ctx.Params.String("id")
	if err := r.Store().SetClientRegistrarIdentity(ctx, id, req.RegistryURI, req.ClientIdentifier, "api"); err != nil {
		ctx.Error(err)
		return
	}
	ctx.StatusCode(fasthttp.StatusNoContent)
}
