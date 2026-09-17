package routes

import (
	"crypto/rand"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	"github.com/dativa-lv/eudi-api-registration/internal/apikeys"
)

// apiKeyCreated is the 201 response for POST /api/clients/{id}/keys (the
// OpenAPI contract's ApiKeyCreated). APIKey is the full display key —
// returned exactly once, never stored, never logged.
type apiKeyCreated struct {
	ClientID string `json:"clientId"`
	Prefix   string `json:"prefix"`
	APIKey   string `json:"apiKey"`
}

// apiCreateKey handles POST /api/clients/{id}/keys: mints a verification key
// for the client. GetClientFull runs FIRST so an unknown id surfaces the
// store's own err:registry:not_found (404) before any key material is
// generated. Only the argon2id PHC hash persists (registry.api_key.secret_hash
// — the model key auth verifies against); this handler emits no log line at
// all, so the display key cannot leak through logging. There is no
// list/revoke operation on this surface — repeated calls simply mint
// additional keys.
func (r *router) apiCreateKey(ctx *azugo.Context) {
	full, err := r.Store().GetClientFull(ctx, ctx.Params.String("id"))
	if err != nil {
		ctx.Error(err)
		return
	}

	key, prefix, phc, err := apikeys.Mint(rand.Reader)
	if err != nil {
		ctx.Error(err)
		return
	}
	if err := r.Store().CreateAPIKey(ctx, full.ID, prefix, phc); err != nil {
		ctx.Error(err)
		return
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(apiKeyCreated{ClientID: full.ID, Prefix: prefix, APIKey: key})
}
