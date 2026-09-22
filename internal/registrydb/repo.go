package registrydb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NOTE: the session service's registrydb is internal to ITS module —
// eudi-api-registration cannot import it. The cross-service contract is the JSON
// stored in the shared registry schema (esp. intended_use.credentials), NOT a
// Go type: IntendedUse and RegisteredCredentialJSON below mirror the session
// service's registrydb definitions field-for-field (single canonical shape) —
// TestRegisteredCredentialJSONMatchesWP10Golden (repo_test.go) pins the JSON
// against a golden fixture so the two modules' independently-defined types can
// never silently drift apart.

// Fixed procedure names (see call() in db.go) — never build these from
// caller input.
const (
	procTransitionClient   = "registry.transition_client"
	procGetClientFull      = "registry.get_client_full"
	procListClientsByState = "registry.list_clients_by_state"
	procCreateDraftClient  = "registry.create_draft_client"
	procSaveWRPDocument    = "registry.save_wrp_document"
	// procAddEvidence / procListEvidence / procGetEvidenceContent back the
	// registry.evidence CRUD trio — NOT dead surface: PurgeOffboarded
	// (below) is the live "-> offboarded" side effect (internal/lifecycle.
	// Service.Transition, called from routes/api.go's apiTransition admin
	// endpoint) and purges evidence blob CONTENT for the offboarded client,
	// so the evidence rows it acts on, and the Go bridge that creates/reads
	// them, stay live surface even though no eudi-api-registration ROUTE calls
	// Add/List/GetEvidenceContent directly today (see internal/lifecycle/
	// lifecycle_test.go's TestTransitionToOffboardedTriggersPurge, which
	// fixtures/verifies the purge through exactly these three methods).
	procAddEvidence                = "registry.add_evidence"
	procListEvidence               = "registry.list_evidence"
	procGetEvidenceContent         = "registry.get_evidence_content"
	procSetClientRegistrarIdentity = "registry.set_client_registrar_identity"
	// procSetClientWebhook is the setter for
	// registry.client.default_webhook_url — see Store.SetClientWebhook's doc
	// comment.
	procSetClientWebhook = "registry.set_client_webhook"
	// procSetClientAllowedOrigins is the setter for
	// registry.client.allowed_origins — see Store.SetClientAllowedOrigins's
	// doc comment.
	procSetClientAllowedOrigins = "registry.set_client_allowed_origins"
	// procSetClientDCAPIMode chooses signed or unsigned browser-based
	// presentation requests for one client, inside registry.client.policy —
	// see Store.SetClientDCAPIMode's doc comment.
	procSetClientDCAPIMode = "registry.set_client_dcapi_mode"
	// procCreateAPIKey is defined by the registry procedures and reused here
	// as-is; registration_api_public has EXECUTE on it. It mints a
	// verification API key for a client via the headless admin API.
	procCreateAPIKey = "registry.create_api_key"
	// procPurgeOffboarded is the live "-> offboarded" side effect
	// (internal/lifecycle.Service.Transition) — see procAddEvidence's doc
	// comment above.
	procPurgeOffboarded = "registry.purge_offboarded"

	procAuditAppend             = "audit.append"
	procAuditListEntries        = "audit.list_entries"
	procAuditLogDeletionRequest = "audit.log_deletion_request"
	procAuditListDeletionReqs   = "audit.list_deletion_requests"

	// procListIntendedUses is defined by the registry procedures and reused
	// here as-is; registration_api_public has EXECUTE on it, so the lifecycle
	// service's "-> active" precondition ("at least one non-revoked intended
	// use") has a read path — see the Store.ListIntendedUses doc comment below.
	procListIntendedUses = "registry.list_intended_uses"
	// procSetIntendedUses (registry.set_intended_uses) is also reused here
	// as-is; registration_api_public has EXECUTE on it, alongside
	// list_intended_uses/create_api_key/revoke_api_key/get_client. Filing
	// confirmation replaces the wizard's pending-<ulid> IntendedUseIdentifier
	// placeholders with the registrar-assigned ones via this procedure. See
	// Store.SetIntendedUses's doc comment for why actor is threaded through a
	// SEPARATE audit.append call rather than atomically.
	procSetIntendedUses = "registry.set_intended_uses"
)

// ClientFull is a registry.client row including the lifecycle columns
// (slug/wrp_document/contact_emails) — a projection the session service's
// registrydb.Client predates. Legal-entity / config data only — never
// attribute values.
type ClientFull struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Status           string          `json:"status"` // 7-state lifecycle state machine
	RegistryURI      string          `json:"registry_uri"`
	ClientIdentifier string          `json:"client_identifier"`
	DefaultWebhook   string          `json:"default_webhook_url"`
	AllowedOrigins   []string        `json:"allowed_origins"`
	Policy           json.RawMessage `json:"policy"`
	Slug             string          `json:"slug"`
	// WRPDocument is the full ts5.WalletRelyingParty JSON (source of truth;
	// intended_use rows are projections). May decode as the literal JSON
	// `null` (json.RawMessage("null")) before the wizard saves a
	// document — check len(doc)==0 or bytes.Equal(doc, []byte("null")) for
	// "not yet submitted", not just len==0.
	WRPDocument   json.RawMessage `json:"wrp_document"`
	ContactEmails []string        `json:"contact_emails"`
}

// ClientSummary is the flat per-client projection registry.list_clients_by_state
// returns; PG.ListClientsByState groups these into map[string][]ClientSummary
// keyed by Status for the operator dashboard. This is the minimal shape the
// dashboard needs; extend here, not by forking a second type, if more fields
// are needed later.
type ClientSummary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Slug      string    `json:"slug,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IntendedUse mirrors the session service's registrydb.IntendedUse
// field-for-field (see the package-level NOTE above).
type IntendedUse struct {
	ID            string                     `json:"id"`
	IntendedUseID string                     `json:"intended_use_id"`
	Purpose       json.RawMessage            `json:"purpose"`
	Credentials   []RegisteredCredentialJSON `json:"credentials"`
	RevokedAt     string                     `json:"revoked_at,omitempty"`
}

// RegisteredCredentialJSON mirrors the session service's
// registrydb.RegisteredCredentialJSON field-for-field — the canonical
// scope-projection JSON shape the session service's dcql.WithinScope path
// reads. The wizard WRITES this shape. TestRegisteredCredentialJSONMatchesWP10Golden
// pins it against a golden fixture shared with the session service's mirror
// definition.
type RegisteredCredentialJSON struct {
	Format         string   `json:"format"`
	DoctypesOrVCTs []string `json:"doctypes_or_vcts"`
	AllClaims      bool     `json:"all_claims"`
	Claims         [][]any  `json:"claims,omitempty"`
}

// Evidence is a registry.evidence row's METADATA only — content is fetched
// separately via GetEvidenceContent (never inlined here: files can be up to
// 10 MiB).
type Evidence struct {
	ID        string    `json:"id"`
	Filename  string    `json:"filename"`
	Mime      string    `json:"mime"`
	SHA256    string    `json:"sha256"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditEntry is an audit.entry row, the read path behind ListAuditEntries —
// the operator client-detail page's "audit trail" needs to list audit.entry
// rows for a client, which AppendAudit (a write-only seam) never provided.
// Detail carries only legal-entity/lifecycle metadata (from/to/reason/
// evidence_ref, filing/evidence ids, etc.) — every write path into
// audit.entry (transition_client, create_draft_client, ...) already enforces
// that no wallet attribute VALUE ever lands here; this is a
// read-back of exactly that data, never a new place values could leak from.
type AuditEntry struct {
	ID       string          `json:"id"`
	At       time.Time       `json:"at"`
	Actor    string          `json:"actor"`
	ClientID string          `json:"client_id"`
	Action   string          `json:"action"`
	Detail   json.RawMessage `json:"detail"`
}

// DeletionRequest is an audit.deletion_request row — ARF TS7 (ARF
// AS-RP-48-004): attribute NAMES only, never values. Its shape
// mirrors the audit.deletion_request columns 1:1.
type DeletionRequest struct {
	ID             string    `json:"id"`
	ClientID       string    `json:"client_id"`
	SessionID      string    `json:"session_id"`
	AttributeNames []string  `json:"attribute_names"`
	RequestedAt    time.Time `json:"requested_at"`
}

// Store is the seam unit tests fake (fake.go) and prod backs with pg (PG
// below). Every method that takes a clientID enforces isolation ON THE
// PROCEDURE SIDE — cross-client access returns registry:not_found (404),
// never a distinguishable 403 (no existence leak). TransitionClient enforces
// the lifecycle state machine and audits every transition atomically with the
// flip.
type Store interface {
	// lifecycle (procedure enforces the transition matrix + audits atomically)
	TransitionClient(ctx context.Context, clientID, toState, actor, evidenceRef, reason string) error
	GetClientFull(ctx context.Context, clientID string) (*ClientFull, error)
	ListClientsByState(ctx context.Context) (map[string][]ClientSummary, error) // dashboard
	CreateDraftClient(ctx context.Context, name, email string, actor string) (string, error)
	// SetClientRegistrarIdentity records the registrar-assigned RegistryURI +
	// ClientIdentifier for clientID. registry.create_draft_client seeds both
	// '', so until an operator sets them every real ARF TS5 check
	// (internal/ts5check) reports "unavailable" — nothing else populates these
	// two columns. The operator learns the values when FILING with the
	// registrar; the caller is the admin endpoint PUT
	// /clients/{id}/registrar-identity (routes/api.go's apiSetRegistrarIdentity).
	// Audited as 'client.set_registrar_identity'.
	SetClientRegistrarIdentity(ctx context.Context, clientID, registryURI, clientIdentifier, actor string) error
	// SetClientWebhook records/replaces clientID's default_webhook_url. It
	// feeds BOTH this service's own ARF TS7 deletion-request webhook
	// (internal/deletion.Flow) AND the session service's session-result
	// webhook (a DIFFERENT service, reading the SAME registry.client column) —
	// without a production setter, no real (non-test) client could ever
	// receive either webhook end-to-end. webhookURL MUST be an absolute https
	// URL (validated by BOTH the implementation and the procedure itself,
	// defense in depth); a malformed value is err:registry:invalid (400), an
	// unknown clientID is err:registry:not_found (404). Audited as
	// 'client.set_webhook'.
	SetClientWebhook(ctx context.Context, clientID, webhookURL, actor string) error
	// SetClientAllowedOrigins records/replaces the web origins clientID may be
	// invoked from. The column is read on every session create by the session
	// service — both to decide whether a redirect or webhook target is one the
	// client pre-registered, and as the origin whitelist for the
	// browser-mediated presentation flow, which cannot run at all without it.
	// Until this setter existed the column could only ever be written at
	// client creation, so that flow was unreachable for any real client.
	//
	// The list is REPLACED, never appended to: it is a whitelist, and an
	// append-only setter offers no way to withdraw an origin. An empty slice
	// is therefore meaningful and allowed — it withdraws the capability.
	// Every entry must be https://host[:port] with no path, query, fragment or
	// userinfo (validated by BOTH the caller and the procedure, defense in
	// depth); a malformed entry is err:registry:invalid (400), an unknown
	// clientID is err:registry:not_found (404). Audited as
	// 'client.set_allowed_origins'.
	SetClientAllowedOrigins(ctx context.Context, clientID string, origins []string, actor string) error
	// SetClientDCAPIMode chooses whether clientID's browser-based presentation
	// requests are signed or unsigned. A signed request lets the wallet
	// authenticate the relying party through its certificate chain and
	// registration data; an unsigned one offers the calling web origin as the
	// only identity. Both are legitimate, and which of them a deployment may
	// offer at all is a deployment-wide setting — this only chooses between the
	// modes already permitted there, so it can never widen the deployment.
	//
	// mode is "signed" or "unsigned" and nothing else; anything else is
	// err:registry:invalid (400) and an unknown clientID is
	// err:registry:not_found (404). The choice is stored inside the client's
	// policy document (merged, never replacing the other verification choices)
	// and recorded even when it matches the default, so that a client someone
	// deliberately left signed reads differently from one nobody ever decided
	// about. Audited as 'client.set_dcapi_mode'.
	SetClientDCAPIMode(ctx context.Context, clientID, mode, actor string) error
	// CreateAPIKey mints a verification API key row for clientID. Only the
	// argon2id PHC hash is stored; the display key never reaches this layer's
	// callers' logs or the database.
	CreateAPIKey(ctx context.Context, clientID, prefix, secretHash string) error
	SaveWRPDocument(ctx context.Context, clientID string, doc json.RawMessage, ius []IntendedUse, actor string) error
	// ListIntendedUses reads back the intended_use projections SaveWRPDocument
	// writes, via registry.list_intended_uses (reused as-is; registration_api_public
	// has EXECUTE on it). The lifecycle service's "-> active" precondition
	// ("at least one non-revoked intended use") needs this read path, and
	// WRPDocument alone (the raw ts5.WalletRelyingParty JSON) is not a
	// substitute — its schema is the wizard's to parse, not this layer's. An
	// unknown clientID yields an empty slice, not an error (matches the
	// procedure's own doc comment: this is a list read, not a single-resource
	// lookup).
	ListIntendedUses(ctx context.Context, clientID string) ([]IntendedUse, error)
	// SetIntendedUses replaces the FULL set of intended uses for clientID via
	// registry.set_intended_uses (reused as-is; registration_api_public has
	// EXECUTE on it — see procSetIntendedUses' doc comment). Its ONE caller is
	// filing confirmation, replacing the wizard's pending-<ulid>
	// IntendedUseIdentifier placeholders (internal/wizard's pendingIUPrefix)
	// with the registrar-assigned ids the operator records at that point.
	//
	// actor is NOT threaded into the reused procedure itself (its signature
	// predates the audit schema — search_path is `registry, util` only, no
	// `audit`) — implementations instead issue a SEPARATE, best-effort
	// audit.append call after a successful replace. This is NOT atomic with
	// the replacement: a crash between the two calls would leave the intended
	// uses updated without a matching audit row. That is a known, accepted
	// gap (not a chosen atomicity strategy) — creating a new lifecycle-guarded
	// SQL procedure was out of scope, so the shared registry.set_intended_uses
	// procedure is reused instead.
	SetIntendedUses(ctx context.Context, clientID string, ius []IntendedUse, actor string) error
	// evidence — see procAddEvidence's doc comment (above): live surface,
	// not dead code, because PurgeOffboarded (below) acts on
	// these same rows.
	AddEvidence(ctx context.Context, clientID string, e *Evidence, content []byte, actor string) (string, error)
	ListEvidence(ctx context.Context, clientID string) ([]Evidence, error)
	GetEvidenceContent(ctx context.Context, clientID, evidenceID string) ([]byte, string, error)
	// audit + deletion log (audit schema)
	AppendAudit(ctx context.Context, actor, clientID, action string, detail json.RawMessage) error
	// ListAuditEntries returns the newest audit.entry rows for clientID (up to
	// limit), via audit.list_entries — the read path counterpart to
	// AppendAudit and the atomic-write procedures, which only write.
	ListAuditEntries(ctx context.Context, clientID string, limit int) ([]AuditEntry, error)
	LogDeletionRequest(ctx context.Context, clientID, sessionID string, attributeNames []string) (string, error)
	ListDeletionRequests(ctx context.Context, clientID string, limit int) ([]DeletionRequest, error)
	PurgeOffboarded(ctx context.Context, clientID string, actor string) error // keys revoked + evidence/doc purge per retention
}

// PG is the production Store: it calls the registry/audit-schema procedures
// through the pgx pool (never raw table SQL).
type PG struct{ pool *pgxpool.Pool }

// NewPG returns a PG-backed Store over pool.
func NewPG(pool *pgxpool.Pool) *PG { return &PG{pool: pool} }

// TransitionClient drives the client lifecycle state machine via
// registry.transition_client. Illegal edges surface as
// err:registry:illegal_transition (409, app.go RegisterReason); an unknown
// clientID surfaces as err:registry:not_found (404).
func (p *PG) TransitionClient(ctx context.Context, clientID, toState, actor, evidenceRef, reason string) error {
	_, err := call(ctx, p.pool, procTransitionClient, map[string]string{
		"client_id": clientID, "to_state": toState, "actor": actor,
		"evidence_ref": evidenceRef, "reason": reason,
	})
	return err
}

// GetClientFull returns the ClientFull projection via registry.get_client_full.
func (p *PG) GetClientFull(ctx context.Context, clientID string) (*ClientFull, error) {
	data, err := call(ctx, p.pool, procGetClientFull, map[string]string{"client_id": clientID})
	if err != nil {
		return nil, err
	}
	var c ClientFull
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ListClientsByState returns every client grouped by Status via
// registry.list_clients_by_state (operator dashboard). The grouping itself
// happens here in Go — the procedure returns a flat list.
func (p *PG) ListClientsByState(ctx context.Context) (map[string][]ClientSummary, error) {
	data, err := call(ctx, p.pool, procListClientsByState, map[string]string{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Clients []ClientSummary `json:"clients"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	grouped := map[string][]ClientSummary{}
	for _, c := range out.Clients {
		grouped[c.Status] = append(grouped[c.Status], c)
	}
	return grouped, nil
}

// CreateDraftClient starts the self-registration lifecycle ([*] -> Draft) via
// registry.create_draft_client.
func (p *PG) CreateDraftClient(ctx context.Context, name, email string, actor string) (string, error) {
	in := map[string]string{"name": name, "actor": actor}
	if email != "" {
		in["email"] = email
	}
	data, err := call(ctx, p.pool, procCreateDraftClient, in)
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// SetClientRegistrarIdentity records the registrar-assigned RegistryURI +
// ClientIdentifier via registry.set_client_registrar_identity.
// err:registry:not_found -> 404 for an unknown clientID.
func (p *PG) SetClientRegistrarIdentity(ctx context.Context, clientID, registryURI, clientIdentifier, actor string) error {
	_, err := call(ctx, p.pool, procSetClientRegistrarIdentity, map[string]string{
		"client_id": clientID, "registry_uri": registryURI, "client_identifier": clientIdentifier, "actor": actor,
	})
	return err
}

// SetClientWebhook records/replaces clientID's default_webhook_url via
// registry.set_client_webhook. Validation (webhookURL must be an absolute
// https URL) happens in the procedure itself — PG never duplicates it
// client-side, same as every other PG method in this file
// (e.g. SetClientRegistrarIdentity above never re-checks non-empty
// registry_uri/client_identifier either).
func (p *PG) SetClientWebhook(ctx context.Context, clientID, webhookURL, actor string) error {
	_, err := call(ctx, p.pool, procSetClientWebhook, map[string]string{
		"client_id": clientID, "webhook_url": webhookURL, "actor": actor,
	})
	return err
}

// SetClientAllowedOrigins records/replaces clientID's allowed_origins via
// registry.set_client_allowed_origins. Origin shape is validated in the
// procedure — PG never duplicates it client-side, same as SetClientWebhook
// above. A nil slice is normalised to an empty array so the procedure always
// receives a JSON array and never null: "withdraw every origin" must be
// expressible, and must not look like "field omitted".
func (p *PG) SetClientAllowedOrigins(ctx context.Context, clientID string, origins []string, actor string) error {
	if origins == nil {
		origins = []string{}
	}
	_, err := call(ctx, p.pool, procSetClientAllowedOrigins, map[string]any{
		"client_id": clientID, "allowed_origins": origins, "actor": actor,
	})
	return err
}

// SetClientDCAPIMode records clientID's browser-request mode via
// registry.set_client_dcapi_mode. The mode vocabulary is validated in the
// procedure, which also owns the translation into the stored policy flag — PG
// never duplicates either, same as SetClientAllowedOrigins above.
func (p *PG) SetClientDCAPIMode(ctx context.Context, clientID, mode, actor string) error {
	_, err := call(ctx, p.pool, procSetClientDCAPIMode, map[string]string{
		"client_id": clientID, "mode": mode, "actor": actor,
	})
	return err
}

// CreateAPIKey mints a verification API key row for clientID via
// registry.create_api_key (reused as-is — see procCreateAPIKey's doc
// comment). secretHash is the argon2id PHC string internal/apikeys.Mint
// produces; the display key itself is never passed to this layer.
func (p *PG) CreateAPIKey(ctx context.Context, clientID, prefix, secretHash string) error {
	_, err := call(ctx, p.pool, procCreateAPIKey, map[string]string{
		"client_id": clientID, "prefix": prefix, "secret_hash": secretHash,
	})
	return err
}

// SaveWRPDocument persists the full ARF TS6 WalletRelyingParty JSON and
// replaces the intended_use projections via registry.save_wrp_document.
func (p *PG) SaveWRPDocument(ctx context.Context, clientID string, doc json.RawMessage, ius []IntendedUse, actor string) error {
	if ius == nil {
		ius = []IntendedUse{} // avoid marshaling a bare JSON null (jsonb_array_elements would error)
	}
	_, err := call(ctx, p.pool, procSaveWRPDocument, map[string]any{
		"client_id": clientID, "doc": doc, "intended_uses": ius, "actor": actor,
	})
	return err
}

// ListIntendedUses returns every intended use registered for clientID via
// registry.list_intended_uses (reused as-is — see the const block above and
// the Store interface doc comment).
func (p *PG) ListIntendedUses(ctx context.Context, clientID string) ([]IntendedUse, error) {
	data, err := call(ctx, p.pool, procListIntendedUses, map[string]string{"client_id": clientID})
	if err != nil {
		return nil, err
	}
	var out struct {
		IntendedUses []IntendedUse `json:"intended_uses"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.IntendedUses, nil
}

// SetIntendedUses replaces the full set of intended uses for clientID via
// registry.set_intended_uses (see the Store interface doc comment for why
// actor is threaded through a separate audit.append call rather than
// atomically with the replacement).
func (p *PG) SetIntendedUses(ctx context.Context, clientID string, ius []IntendedUse, actor string) error {
	if ius == nil {
		ius = []IntendedUse{} // avoid marshaling a bare JSON null (jsonb_array_elements would error)
	}
	if _, err := call(ctx, p.pool, procSetIntendedUses, map[string]any{
		"client_id": clientID, "intended_uses": ius,
	}); err != nil {
		return err
	}
	detail, _ := json.Marshal(map[string]int{"intended_use_count": len(ius)})
	return p.AppendAudit(ctx, actor, clientID, "client.set_intended_uses", detail)
}

// AddEvidence stores a new evidence blob via registry.add_evidence. content
// is base64-encoded on the wire (the procedure decodes it server-side); e's
// Filename/Mime/SHA256/SizeBytes are computed server-side from the uploaded
// multipart file. On success e.ID/e.CreatedAt are filled in.
func (p *PG) AddEvidence(ctx context.Context, clientID string, e *Evidence, content []byte, actor string) (string, error) {
	data, err := call(ctx, p.pool, procAddEvidence, map[string]any{
		"client_id": clientID, "filename": e.Filename, "mime": e.Mime,
		"sha256": e.SHA256, "size_bytes": e.SizeBytes,
		"content":     base64.StdEncoding.EncodeToString(content),
		"uploaded_by": actor, "actor": actor,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	e.ID = out.ID
	e.CreatedAt = out.CreatedAt
	return out.ID, nil
}

// ListEvidence returns evidence METADATA (never content) for clientID via
// registry.list_evidence.
func (p *PG) ListEvidence(ctx context.Context, clientID string) ([]Evidence, error) {
	data, err := call(ctx, p.pool, procListEvidence, map[string]string{"client_id": clientID})
	if err != nil {
		return nil, err
	}
	var out struct {
		Evidence []Evidence `json:"evidence"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Evidence, nil
}

// GetEvidenceContent fetches one evidence blob's bytes + mime type via
// registry.get_evidence_content (err:registry:not_found -> 404 for another
// client's or an unknown evidence id — no existence leak).
func (p *PG) GetEvidenceContent(ctx context.Context, clientID, evidenceID string) ([]byte, string, error) {
	data, err := call(ctx, p.pool, procGetEvidenceContent,
		map[string]string{"client_id": clientID, "evidence_id": evidenceID})
	if err != nil {
		return nil, "", err
	}
	var out struct {
		Content string `json:"content"`
		Mime    string `json:"mime"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, "", err
	}
	raw, err := base64.StdEncoding.DecodeString(out.Content)
	if err != nil {
		return nil, "", fmt.Errorf("registrydb: decode evidence content: %w", err)
	}
	return raw, out.Mime, nil
}

// AppendAudit writes one general-purpose audit.entry row via audit.append.
// Unlike TransitionClient/PurgeOffboarded (which audit themselves atomically
// with their state change, inside the same procedure), this is the explicit
// call sites elsewhere in this service make when they need an audit trail
// entry for something that isn't a lifecycle transition.
func (p *PG) AppendAudit(ctx context.Context, actor, clientID, action string, detail json.RawMessage) error {
	if len(detail) == 0 {
		detail = json.RawMessage(`{}`)
	}
	in := map[string]any{"actor": actor, "action": action, "detail": detail}
	if clientID != "" {
		in["client_id"] = clientID
	}
	_, err := call(ctx, p.pool, procAuditAppend, in)
	return err
}

// ListAuditEntries returns the newest audit.entry rows for clientID (up to
// limit) via audit.list_entries.
func (p *PG) ListAuditEntries(ctx context.Context, clientID string, limit int) ([]AuditEntry, error) {
	data, err := call(ctx, p.pool, procAuditListEntries, map[string]any{"client_id": clientID, "limit": limit})
	if err != nil {
		return nil, err
	}
	var out struct {
		Entries []AuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

// LogDeletionRequest writes the ARF TS7 deletion-request log entry via
// audit.log_deletion_request (ARF AS-RP-48-004). attributeNames MUST be
// attribute NAMES only — this is the single chokepoint that enforces it;
// callers must never pass values here.
func (p *PG) LogDeletionRequest(ctx context.Context, clientID, sessionID string, attributeNames []string) (string, error) {
	if attributeNames == nil {
		attributeNames = []string{}
	}
	data, err := call(ctx, p.pool, procAuditLogDeletionRequest, map[string]any{
		"client_id": clientID, "session_id": sessionID, "attribute_names": attributeNames,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// ListDeletionRequests returns the newest deletion-request log entries for
// clientID via audit.list_deletion_requests.
func (p *PG) ListDeletionRequests(ctx context.Context, clientID string, limit int) ([]DeletionRequest, error) {
	data, err := call(ctx, p.pool, procAuditListDeletionReqs, map[string]any{"client_id": clientID, "limit": limit})
	if err != nil {
		return nil, err
	}
	var out struct {
		Requests []DeletionRequest `json:"requests"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Requests, nil
}

// PurgeOffboarded purges an offboarded client's evidence blob CONTENT (never
// its metadata) and revokes its api_keys via registry.purge_offboarded
// (err:registry:invalid -> 400 when the client is not yet offboarded). Legal
// entity data (wrp_document, filings, etc.) is RETAINED per retention policy.
func (p *PG) PurgeOffboarded(ctx context.Context, clientID string, actor string) error {
	_, err := call(ctx, p.pool, procPurgeOffboarded, map[string]string{"client_id": clientID, "actor": actor})
	return err
}
