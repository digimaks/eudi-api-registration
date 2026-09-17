package registrydb

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fake is the in-memory Store for unit tests (no network). It mirrors
// procedure semantics: client isolation is enforced on every call (wrong
// client_id -> registry:not_found, no existence leak), TransitionClient
// enforces the exact lifecycle matrix and audits atomically with the flip,
// and PurgeOffboarded purges evidence CONTENT only (metadata retained) —
// same discipline as the real registry procedures. The evidence trio +
// PurgeOffboarded are live surface — the "-> offboarded" purge side effect
// (internal/lifecycle.Service.Transition), not dead code.
type Fake struct {
	mu sync.Mutex

	clients         map[string]*ClientFull
	clientUpdatedAt map[string]time.Time // clientID -> updated_at (ClientFull has no field for this; tracked out-of-band, same rows registry.transition_client/save_wrp_document touch)

	intendedUses map[string]map[string]*IntendedUse // clientID -> intendedUseID -> row
	// intendedUseOrder tracks, per client, the order in which each
	// intended_use_id was FIRST seen — i.e. its insertion/created_at order,
	// mirroring registry.intended_use.created_at (registry.list_intended_uses
	// orders "by iu.created_at"). IntendedUse itself carries no CreatedAt
	// field (see the struct doc comment), so this out-of-band slice is the
	// Fake's substitute — same discipline as clientUpdatedAt above.
	// SaveWRPDocument's replace-all upsert PRESERVES an existing id's
	// position here (mirroring the real procedure's "on conflict do update",
	// which never touches created_at) and appends brand-new ids at the end,
	// in the order they appear in that call's ius slice; a dropped id is
	// removed. ListIntendedUses walks this slice instead of sorting the map
	// lexicographically by IntendedUseID — the two orderings coincide only
	// by accident (e.g. "iu-1", "iu-2"), and diverge whenever a client's
	// intended uses are registered out of lexicographic order.
	intendedUseOrder map[string][]string // clientID -> intendedUseID, oldest first

	evidence map[string]*fakeEvidence // evidenceID -> row

	auditLog         []AuditLogEntry
	deletionRequests map[string][]DeletionRequest // clientID -> rows, append order (oldest first)

	apiKeys map[string][]FakeAPIKey // clientID -> minted key rows, append order (oldest first)

	seq int
}

// FakeAPIKey is a Fake-only introspection row for one minted verification API
// key (mirroring registry.api_key's Prefix/SecretHash columns — never the
// display key itself, which this layer never sees: routes/api_keys.go passes
// CreateAPIKey only the argon2id PHC hash apikeys.Mint produced).
type FakeAPIKey struct {
	Prefix     string
	SecretHash string
}

type fakeEvidence struct {
	Evidence
	ClientID string
	Content  []byte
}

// AuditLogEntry is a Fake-only introspection type (NOT part of Store) — lets
// tests assert a procedure's audited side effect directly, without going
// through the Store.ListAuditEntries read path. It is the broader, unscoped
// introspection seam — AuditLog() returns every entry ever recorded, across
// all clients, which ListAuditEntries deliberately does not. Mirrors exactly
// which procedures write audit.entry directly: every registry procedure whose
// Store method signature threads an `actor` (TransitionClient,
// CreateDraftClient, SaveWRPDocument, AddEvidence, PurgeOffboarded) plus any
// explicit AppendAudit call. ID/At mirror the real audit.entry row's primary
// key and timestamp, so this type can convert losslessly to the Store-facing
// AuditEntry.
type AuditLogEntry struct {
	ID, Actor, ClientID, Action string
	At                          time.Time
	Detail                      json.RawMessage
}

// NewFake returns an empty in-memory Store.
func NewFake() *Fake {
	return &Fake{
		clients:          map[string]*ClientFull{},
		clientUpdatedAt:  map[string]time.Time{},
		intendedUses:     map[string]map[string]*IntendedUse{},
		intendedUseOrder: map[string][]string{},
		evidence:         map[string]*fakeEvidence{},
		deletionRequests: map[string][]DeletionRequest{},
		apiKeys:          map[string][]FakeAPIKey{},
	}
}

// nextID mints a fake 26-char ULID-shaped id — uniqueness is all that
// matters for the fake, not real ULID monotonicity.
func (f *Fake) nextID() string {
	f.seq++
	return fmt.Sprintf("01JZXREGDBFAKE%012d", f.seq)
}

// slugNonAlnum mirrors registry.create_draft_client's own
// regexp_replace(..., '[^a-z0-9]+', '-', 'g').
var slugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// slugify mirrors registry.create_draft_client's slug generation: lowercase
// the name, collapse every run of non [a-z0-9] characters to a single '-',
// trim leading/trailing '-', fall back to "client" if nothing alphanumeric
// survives, cap at 40 chars (re-trimming any '-' the cap lands on), then
// append a short, deterministic uniqueness suffix drawn from id — the SAME
// id CreateDraftClient mints for this row, so two clients registered with
// the identical name still get distinct slugs (each has its own id), exactly
// like the real procedure's ULID-suffix approach. See that procedure's doc
// comment for the full reasoning; this is the Fake's mirror, not a
// byte-for-byte reproduction (id shapes differ —
// see nextID's doc comment — so the two implementations can never produce
// identical slugs for the same input, only the same COLLISION-SAFETY
// property).
func slugify(name, id string) string {
	base := strings.ToLower(strings.TrimSpace(name))
	base = slugNonAlnum.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "client"
	}
	if len(base) > 40 {
		base = base[:40]
	}
	base = strings.TrimRight(base, "-")

	suffix := id
	if len(suffix) > 7 {
		suffix = suffix[len(suffix)-7:]
	}
	return base + "-" + strings.ToLower(suffix)
}

func emptyDetail(d json.RawMessage) json.RawMessage {
	if len(d) == 0 {
		return json.RawMessage(`{}`)
	}
	return d
}

func (f *Fake) audit(actor, clientID, action string, detail json.RawMessage) {
	f.auditLog = append(f.auditLog, AuditLogEntry{
		ID: f.nextID(), At: time.Now().UTC(),
		Actor: actor, ClientID: clientID, Action: action, Detail: emptyDetail(detail),
	})
}

// AuditLog returns a copy of every audit entry recorded so far, oldest
// first. Test-only introspection (see AuditLogEntry's doc comment).
func (f *Fake) AuditLog() []AuditLogEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]AuditLogEntry, len(f.auditLog))
	copy(out, f.auditLog)
	return out
}

// TestSetClientStatus force-sets a client's lifecycle status, bypassing the
// transition matrix — a test-only seam (NOT part of Store) so table tests
// can start each edge from an arbitrary state without walking the whole
// chain. The real schema has no equivalent bypass (status only ever changes
// via registry.transition_client).
func (f *Fake) TestSetClientStatus(clientID, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[clientID]; ok {
		c.Status = status
	}
}

// TestSetClientRegistrarIdentity force-sets a client's RegistryURI/
// ClientIdentifier — a raw, unaudited test-only seam (NOT part of Store),
// used by internal/ts5check's own fixtures to seed a client directly without
// driving a real flow. The real (audited) Store.SetClientRegistrarIdentity
// (below in this file) is called from routes/api.go's apiSetRegistrarIdentity
// (PUT /api/clients/{id}/registrar-identity); this force-setter remains only
// for tests that want to seed the value without exercising that endpoint.
func (f *Fake) TestSetClientRegistrarIdentity(clientID, registryURI, clientIdentifier string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[clientID]; ok {
		c.RegistryURI = registryURI
		c.ClientIdentifier = clientIdentifier
	}
}

// TestSetClientWebhook force-sets a client's DefaultWebhook — a test-only
// seam (NOT part of Store), same as TestSetClientRegistrarIdentity above.
// A populated DefaultWebhook is consumed by this service's ARF TS7
// DeletionRequestEvent webhook (internal/deletion); this seam seeds it
// directly without exercising the real (audited) Store.SetClientWebhook
// (below in this file).
func (f *Fake) TestSetClientWebhook(clientID, webhookURL string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[clientID]; ok {
		c.DefaultWebhook = webhookURL
	}
}

// TestSetClientPolicy force-sets a client's stored policy document — a
// test-only seam (NOT part of Store), same as TestSetClientWebhook above. It
// exists so a test can put a verification choice in place that no Store method
// writes today, and then assert an unrelated setter left it alone.
func (f *Fake) TestSetClientPolicy(clientID string, policy json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[clientID]; ok {
		c.Policy = policy
	}
}

// legalTransitions is the ONLY set of legal edges (the lifecycle state
// machine; ARF Topic 52) — kept in exact lockstep with
// registry.transition_client's `v_legal` IN-list.
var legalTransitions = map[[2]string]bool{
	{"draft", "evidence_submitted"}:                true,
	{"evidence_submitted", "filed_with_registrar"}: true,
	{"filed_with_registrar", "registered"}:         true,
	{"registered", "active"}:                       true,
	{"active", "suspended"}:                        true,
	{"suspended", "active"}:                        true,
	{"suspended", "offboarded"}:                    true,
	{"active", "offboarded"}:                       true,
}

// TransitionClient drives the client lifecycle state machine, mirroring
// registry.transition_client: an unknown clientID is registry:not_found; an
// edge outside legalTransitions is registry:illegal_transition (no partial
// write); a legal edge flips the status and audits atomically.
func (f *Fake) TransitionClient(_ context.Context, clientID, toState, actor, evidenceRef, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.clients[clientID]
	if !ok {
		return resultError("registry:not_found")
	}
	from := c.Status
	if !legalTransitions[[2]string{from, toState}] {
		return resultError("registry:illegal_transition")
	}

	c.Status = toState
	f.clientUpdatedAt[clientID] = time.Now().UTC()
	detail, _ := json.Marshal(map[string]string{
		"from": from, "to": toState, "evidence_ref": evidenceRef, "reason": reason,
	})
	f.audit(actor, clientID, "client.transition", detail)
	return nil
}

// GetClientFull returns a copy of the stored client, or registry:not_found.
func (f *Fake) GetClientFull(_ context.Context, clientID string) (*ClientFull, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[clientID]
	if !ok {
		return nil, resultError("registry:not_found")
	}
	cp := *c
	return &cp, nil
}

// ListClientsByState groups every client by Status (operator dashboard).
func (f *Fake) ListClientsByState(_ context.Context) (map[string][]ClientSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	grouped := map[string][]ClientSummary{}
	for _, c := range f.clients {
		grouped[c.Status] = append(grouped[c.Status], ClientSummary{
			ID: c.ID, Name: c.Name, Status: c.Status, Slug: c.Slug, UpdatedAt: f.clientUpdatedAt[c.ID],
		})
	}
	// f.clients is a map — sort each state's slice by ID for determinism
	// (mirrors the SQL procedure's "order by c.status, c.updated_at desc,
	// c.id desc" tie-break; exact updated_at ordering isn't reproduced here
	// since ties are common with time.Now()'s resolution across a fast test).
	for status := range grouped {
		sort.Slice(grouped[status], func(i, j int) bool { return grouped[status][i].ID < grouped[status][j].ID })
	}
	return grouped, nil
}

// CreateDraftClient inserts a new draft client ([*] -> Draft), auto-generates
// its public slug (see slugify's doc comment; mirrors
// registry.create_draft_client's own generation — GetClientFull/
// ListClientsByState project Slug; the registry.client.slug column is live),
// and audits 'client.create'.
func (f *Fake) CreateDraftClient(_ context.Context, name, email string, actor string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextID()
	emails := []string{}
	if email != "" {
		emails = []string{email}
	}
	f.clients[id] = &ClientFull{
		ID: id, Name: name, Status: "draft", AllowedOrigins: []string{},
		Policy: json.RawMessage(`{}`), ContactEmails: emails, Slug: slugify(name, id),
	}
	f.clientUpdatedAt[id] = time.Now().UTC()
	detail, _ := json.Marshal(map[string]string{"name": name})
	f.audit(actor, id, "client.create", detail)
	return id, nil
}

// SetClientRegistrarIdentity records the registrar-assigned RegistryURI +
// ClientIdentifier for clientID, mirroring registry.set_client_registrar_identity
// — an unknown clientID is registry:not_found. Audited as
// 'client.set_registrar_identity'. Distinct from the pre-existing
// TestSetClientRegistrarIdentity (a raw, unaudited test-only bypass used by
// internal/ts5check's own fixtures to seed a client directly) — this is the
// real Store method, called from the PUT /clients/{id}/registrar-identity
// admin endpoint (routes/api.go's apiSetRegistrarIdentity).
func (f *Fake) SetClientRegistrarIdentity(_ context.Context, clientID, registryURI, clientIdentifier, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[clientID]
	if !ok {
		return resultError("registry:not_found")
	}
	c.RegistryURI = registryURI
	c.ClientIdentifier = clientIdentifier
	f.clientUpdatedAt[clientID] = time.Now().UTC()
	detail, _ := json.Marshal(map[string]string{"registry_uri": registryURI, "client_identifier": clientIdentifier})
	f.audit(actor, clientID, "client.set_registrar_identity", detail)
	return nil
}

// webhookURLPattern mirrors registry.set_client_webhook's own
// '^https://[^[:space:]]+$' check — an independent Go-side re-implementation
// of the SAME validation shape, not a shared helper, matching this file's
// existing convention of mirroring SQL
// semantics rather than sharing code with the procedure (e.g. slugify above
// mirrors create_draft_client's slug generation the same way).
var webhookURLPattern = regexp.MustCompile(`^https://\S+$`)

// SetClientWebhook records/replaces clientID's DefaultWebhook, mirroring
// registry.set_client_webhook (see the Store interface's doc comment for why
// this setter is needed). Rejects a malformed (non-absolute-https) URL with
// the same registry:invalid code the procedure uses, and an unknown clientID
// with registry:not_found. Audited as 'client.set_webhook'.
func (f *Fake) SetClientWebhook(_ context.Context, clientID, webhookURL, actor string) error {
	if webhookURL == "" || !webhookURLPattern.MatchString(webhookURL) {
		return resultError("registry:invalid")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[clientID]
	if !ok {
		return resultError("registry:not_found")
	}
	c.DefaultWebhook = webhookURL
	f.clientUpdatedAt[clientID] = time.Now().UTC()
	detail, _ := json.Marshal(map[string]string{"webhook_url": webhookURL})
	f.audit(actor, clientID, "client.set_webhook", detail)
	return nil
}

// webOriginPattern mirrors registry.set_client_allowed_origins's own regex —
// https://host[:port] and nothing else. A deliberate re-statement of the SAME
// validation shape rather than a shared helper, matching this file's existing
// convention (see webhookURLPattern above).
var webOriginPattern = regexp.MustCompile(`^https://[^\s/?#@]+$`)

// SetClientAllowedOrigins records/replaces clientID's AllowedOrigins,
// mirroring registry.set_client_allowed_origins (see the Store interface's doc
// comment for why this setter is needed). Rejects a malformed entry or an
// over-long list with the same registry:invalid code the procedure uses, and
// an unknown clientID with registry:not_found. An empty list is valid and
// withdraws every origin. Audited as 'client.set_allowed_origins'.
func (f *Fake) SetClientAllowedOrigins(_ context.Context, clientID string, origins []string, actor string) error {
	if len(origins) > 20 {
		return resultError("registry:invalid")
	}
	for _, o := range origins {
		if !webOriginPattern.MatchString(o) {
			return resultError("registry:invalid")
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[clientID]
	if !ok {
		return resultError("registry:not_found")
	}
	// Copy: the caller's slice must not alias stored state, or a later
	// mutation by the caller would silently rewrite the whitelist.
	stored := make([]string, len(origins))
	copy(stored, origins)
	c.AllowedOrigins = stored
	f.clientUpdatedAt[clientID] = time.Now().UTC()
	detail, _ := json.Marshal(map[string][]string{"allowed_origins": stored})
	f.audit(actor, clientID, "client.set_allowed_origins", detail)
	return nil
}

// SetClientDCAPIMode records clientID's browser-request mode, mirroring
// registry.set_client_dcapi_mode (see the Store interface's doc comment).
// Anything but "signed" or "unsigned" is registry:invalid and an unknown
// clientID is registry:not_found. The flag is MERGED into the stored policy
// document rather than replacing it, exactly as the procedure does — a fake
// that overwrote the other verification choices would let a test pass while
// the real thing silently reset them. Audited as 'client.set_dcapi_mode'.
func (f *Fake) SetClientDCAPIMode(_ context.Context, clientID, mode, actor string) error {
	if mode != "signed" && mode != "unsigned" {
		return resultError("registry:invalid")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[clientID]
	if !ok {
		return resultError("registry:not_found")
	}
	policy := map[string]any{}
	if len(c.Policy) > 0 {
		if err := json.Unmarshal(c.Policy, &policy); err != nil {
			return resultError("registry:error")
		}
	}
	policy["require_signed_dcapi"] = mode == "signed"
	merged, err := json.Marshal(policy)
	if err != nil {
		return resultError("registry:error")
	}
	c.Policy = merged
	f.clientUpdatedAt[clientID] = time.Now().UTC()
	detail, _ := json.Marshal(map[string]string{"mode": mode})
	f.audit(actor, clientID, "client.set_dcapi_mode", detail)
	return nil
}

// CreateAPIKey mints a verification API key row for clientID, mirroring
// registry.create_api_key: an unknown clientID is registry:not_found (no key
// material is recorded) -- same "check client exists first" discipline as
// every other client-scoped Fake method (e.g. AddEvidence above). Only
// Prefix/SecretHash are retained; the Fake never sees the display key at all
// (routes/api_keys.go passes only the argon2id PHC hash apikeys.Mint
// produced).
func (f *Fake) CreateAPIKey(_ context.Context, clientID, prefix, secretHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[clientID]; !ok {
		return resultError("registry:not_found")
	}
	f.apiKeys[clientID] = append(f.apiKeys[clientID], FakeAPIKey{Prefix: prefix, SecretHash: secretHash})
	return nil
}

// APIKeys returns a copy of every key minted for clientID so far, oldest
// first -- test-only introspection (NOT part of Store), same "copy out,
// never let a caller mutate internal state" discipline as AuditLog() above.
func (f *Fake) APIKeys(clientID string) []FakeAPIKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]FakeAPIKey, len(f.apiKeys[clientID]))
	copy(out, f.apiKeys[clientID])
	return out
}

// SaveWRPDocument persists the full ARF TS6 document and replace-all upserts
// the intended_use projections, mirroring registry.save_wrp_document.
func (f *Fake) SaveWRPDocument(_ context.Context, clientID string, doc json.RawMessage, ius []IntendedUse, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[clientID]
	if !ok {
		return resultError("registry:not_found")
	}
	for _, iu := range ius {
		if iu.IntendedUseID == "" {
			return resultError("registry:invalid")
		}
	}

	c.WRPDocument = append(json.RawMessage(nil), doc...)
	f.clientUpdatedAt[clientID] = time.Now().UTC()

	f.replaceIntendedUsesLocked(clientID, ius)

	detail, _ := json.Marshal(map[string]int{"intended_use_count": len(ius)})
	f.audit(actor, clientID, "client.save_wrp_document", detail)
	return nil
}

// replaceIntendedUsesLocked performs the replace-all upsert BOTH
// SaveWRPDocument (the wizard's initial submission) and SetIntendedUses
// (filing confirmation replacing pending-<ulid> placeholders with
// registrar-assigned ids) apply to a client's intended_use
// projections — mirrors registry.set_intended_uses / the intended_use half
// of registry.save_wrp_document (both SQL procedures share the identical
// validate-then-replace-all shape). Factored out so the two Store methods
// cannot silently diverge in how they rebuild intendedUseOrder. Caller holds
// f.mu and has already validated every iu.IntendedUseID is non-empty.
//
// An existing row is matched by IntendedUseID (the business key, exactly
// the real procedure's "on conflict (client_id, intended_use_id) do
// update" target) and, when found, KEEPS its internal ID across the
// replace — mirroring the real procedure, which never touches the primary
// key on an update. This only helps when a call re-submits the SAME
// IntendedUseID it already had (e.g. SaveWRPDocument called twice with an
// unchanged id — TestListIntendedUsesOrdersByInsertionNotLexicographically).
// It does NOT preserve identity across a RENAME: SetIntendedUses' one real
// caller (filing confirmation) always submits a DIFFERENT IntendedUseID (the
// registrar-assigned one replacing a pending-<ulid> placeholder) for the SAME
// logical row, and there is no
// business key left to match the old entry by — a fresh internal ID is
// minted for it, exactly mirroring what the real procedure does too: its
// ON CONFLICT target can't match an identifier that no longer exists, so
// it INSERTs a new row (fresh id) for the new identifier, and the
// procedure's own subsequent `delete ... where not (intended_use_id = any
// (v_keep))` removes the now-orphaned old row. The internal ID is never
// exposed to any route/handler logic, so this has no observable effect
// beyond this package's own bookkeeping.
func (f *Fake) replaceIntendedUsesLocked(clientID string, ius []IntendedUse) {
	existing := f.intendedUses[clientID]
	m := make(map[string]*IntendedUse, len(ius))
	for i := range ius {
		iu := ius[i]
		if iu.ID == "" {
			if old, ok := existing[iu.IntendedUseID]; ok {
				iu.ID = old.ID
			} else {
				iu.ID = f.nextID()
			}
		}
		m[iu.IntendedUseID] = &iu
	}
	f.intendedUses[clientID] = m

	// Rebuild the order slice: ids already known (from a prior call) KEEP
	// their existing position — mirroring the real procedure's upsert,
	// which never touches an existing row's created_at — and any brand-new
	// id (first seen in this call's ius) is appended at the end, in the
	// order it appears in ius. An id dropped from this call (not in m
	// anymore) drops out of the order too, matching the delete below it.
	order := make([]string, 0, len(m))
	for _, id := range f.intendedUseOrder[clientID] {
		if _, kept := m[id]; kept {
			order = append(order, id)
		}
	}
	seen := make(map[string]bool, len(order))
	for _, id := range order {
		seen[id] = true
	}
	for i := range ius {
		id := ius[i].IntendedUseID
		if !seen[id] {
			seen[id] = true
			order = append(order, id)
		}
	}
	f.intendedUseOrder[clientID] = order
}

// SetIntendedUses replaces the full set of intended uses for clientID,
// mirroring registry.set_intended_uses — see the Store interface doc
// comment for why actor is recorded via a separate f.audit call rather than
// atomically (mirrored here even though the Fake COULD trivially make it
// atomic, specifically so a test against the Fake cannot observe a stronger
// atomicity guarantee than the real PG-backed Store provides).
func (f *Fake) SetIntendedUses(_ context.Context, clientID string, ius []IntendedUse, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[clientID]; !ok {
		return resultError("registry:not_found")
	}
	for _, iu := range ius {
		if iu.IntendedUseID == "" {
			return resultError("registry:invalid")
		}
	}

	f.replaceIntendedUsesLocked(clientID, ius)

	detail, _ := json.Marshal(map[string]int{"intended_use_count": len(ius)})
	f.audit(actor, clientID, "client.set_intended_uses", detail)
	return nil
}

// ListIntendedUses returns every intended use registered for clientID, in
// insertion (created_at) order — mirroring registry.list_intended_uses'
// "order by iu.created_at, iu.id" (see intendedUseOrder's doc comment). An
// unknown client yields an empty slice, not an error (same as the session
// service's registrydb.Fake — the two Stores' Fakes independently mirror the
// same procedure's documented behavior).
//
// The real procedure's ORDER BY carries an `id` tiebreak because "order by
// created_at" ALONE is unstable across calls for rows inserted in the SAME
// transaction (save_wrp_document/set_intended_uses insert every row of one
// call inside one transaction, so they share one created_at — Postgres does
// not guarantee any particular relative order for ties without a secondary
// key). This Fake's intendedUseOrder slice is ALREADY a total, deterministic
// order (a slice index never ties), so it needs no code change for
// determinism — but it does NOT, and cannot, reproduce the REAL procedure's
// tie-break value-for-value: `id` there is a ULID keyed on clock_timestamp()
// + random bits, so rows created in the same instant sort by their random
// suffix, not by insertion/loop order, while this Fake preserves insertion
// order for exactly those rows. Route logic MUST NOT rely on either ordering
// to recover "which entry is which" — the filing-confirmation handler maps by
// each entry's OWN IntendedUseID (a stable key), never by this list's
// position, which is what actually makes correctness independent of both
// orderings.
func (f *Fake) ListIntendedUses(_ context.Context, clientID string) ([]IntendedUse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.intendedUses[clientID]
	out := make([]IntendedUse, 0, len(m))
	for _, id := range f.intendedUseOrder[clientID] {
		if iu, ok := m[id]; ok {
			out = append(out, *iu)
		}
	}
	return out, nil
}

// AddEvidence stores a new evidence blob, mirroring registry.add_evidence.
func (f *Fake) AddEvidence(_ context.Context, clientID string, e *Evidence, content []byte, actor string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[clientID]; !ok {
		return "", resultError("registry:not_found")
	}
	id := f.nextID()
	now := time.Now().UTC()
	cp := *e
	cp.ID = id
	cp.CreatedAt = now
	f.evidence[id] = &fakeEvidence{Evidence: cp, ClientID: clientID, Content: append([]byte(nil), content...)}
	e.ID = id
	e.CreatedAt = now
	detail, _ := json.Marshal(map[string]string{"evidence_id": id, "filename": e.Filename})
	f.audit(actor, clientID, "evidence.add", detail)
	return id, nil
}

// ListEvidence returns evidence METADATA only, mirroring registry.list_evidence.
func (f *Fake) ListEvidence(_ context.Context, clientID string) ([]Evidence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Evidence{}
	for _, row := range f.evidence {
		if row.ClientID == clientID {
			out = append(out, row.Evidence)
		}
	}
	// f.evidence is a map — sort explicitly (mirrors SQL's "order by
	// created_at, id"; id as tie-break since CreatedAt has second-level
	// duplicates possible from fast successive calls in a test).
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// GetEvidenceContent returns one evidence blob's bytes + mime, scoped to
// clientID (another client's evidence id -> registry:not_found, no
// existence leak) — mirrors registry.get_evidence_content.
func (f *Fake) GetEvidenceContent(_ context.Context, clientID, evidenceID string) ([]byte, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.evidence[evidenceID]
	if !ok || row.ClientID != clientID {
		return nil, "", resultError("registry:not_found")
	}
	return append([]byte(nil), row.Content...), row.Mime, nil
}

// AppendAudit writes one general-purpose audit entry, mirroring audit.append.
func (f *Fake) AppendAudit(_ context.Context, actor, clientID, action string, detail json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if actor == "" || action == "" {
		return resultError("audit:invalid")
	}
	f.audit(actor, clientID, action, detail)
	return nil
}

// ListAuditEntries returns the newest audit.entry rows for clientID (up to
// limit), mirroring audit.list_entries — the client-scoped, Store-facing
// counterpart to AuditLog() above.
func (f *Fake) ListAuditEntries(_ context.Context, clientID string, limit int) ([]AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	matched := make([]AuditLogEntry, 0, len(f.auditLog))
	for _, e := range f.auditLog {
		if e.ClientID == clientID {
			matched = append(matched, e)
		}
	}
	out := make([]AuditEntry, 0, len(matched))
	for i := len(matched) - 1; i >= 0 && len(out) < limit; i-- {
		e := matched[i]
		out = append(out, AuditEntry{
			ID: e.ID, At: e.At, Actor: e.Actor, ClientID: e.ClientID, Action: e.Action, Detail: e.Detail,
		})
	}
	return out, nil
}

// LogDeletionRequest writes the ARF TS7 deletion-request log entry, mirroring
// audit.log_deletion_request. attributeNames MUST be attribute NAMES only —
// callers must never pass values here. A nil slice is accepted
// (not audit:invalid): PG.LogDeletionRequest (repo.go) converts
// nil->[]string{} before calling the procedure, and the procedure itself
// only rejects a MISSING attribute_names key, never an empty array — so nil
// must succeed here exactly as it does against the real DB.
func (f *Fake) LogDeletionRequest(_ context.Context, clientID, sessionID string, attributeNames []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if clientID == "" || sessionID == "" {
		return "", resultError("audit:invalid")
	}
	id := f.nextID()
	names := []string{}
	if attributeNames != nil {
		names = append([]string(nil), attributeNames...)
	}
	f.deletionRequests[clientID] = append(f.deletionRequests[clientID], DeletionRequest{
		ID: id, ClientID: clientID, SessionID: sessionID, AttributeNames: names, RequestedAt: time.Now().UTC(),
	})
	return id, nil
}

// ListDeletionRequests returns the newest-first deletion-request log entries
// for clientID, mirroring audit.list_deletion_requests.
func (f *Fake) ListDeletionRequests(_ context.Context, clientID string, limit int) ([]DeletionRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.deletionRequests[clientID]
	out := make([]DeletionRequest, 0, len(rows))
	for i := len(rows) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, rows[i])
	}
	return out, nil
}

// PurgeOffboarded purges an offboarded client's evidence blob CONTENT
// (metadata retained), mirroring registry.purge_offboarded. Legal-entity
// data (wrp_document, filings, etc.) is RETAINED per retention policy. The
// Fake has no api_key rows to revoke (that table belongs to the session
// service's registrydb, a different Store this one cannot see); the real
// procedure's api_key revocation has no Fake-visible counterpart here.
func (f *Fake) PurgeOffboarded(_ context.Context, clientID string, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[clientID]
	if !ok {
		return resultError("registry:not_found")
	}
	if c.Status != "offboarded" {
		return resultError("registry:invalid")
	}
	for _, row := range f.evidence {
		if row.ClientID == clientID {
			row.Content = nil
		}
	}
	f.audit(actor, clientID, "client.purge", json.RawMessage(`{}`))
	return nil
}
