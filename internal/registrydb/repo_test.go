package registrydb

import (
	"encoding/json"
	"testing"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/go-quicktest/qt"
)

// registry:illegal_transition only maps to 409 once the "illegal-transition"
// reason is registered (app.go, at service startup). This test binary never
// runs app.go's init (registrydb can't import the eudiapiregistration package:
// eudiapiregistration imports registrydb, not the reverse), so mirror that one
// RegisterReason call here — keep it in sync with app.go. Same pattern as the
// session service's registrydb and sessiondb repo tests.
func init() {
	pkerrors.RegisterReason("illegalTransition", pkerrors.ReasonSpec{Status: 409, Title: "Illegal client-lifecycle transition"})
}

type statusCoder interface{ StatusCode() int }

func mustStatus(t *testing.T, err error) int {
	t.Helper()
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	return sc.StatusCode()
}

func TestParseEnvelopeSuccess(t *testing.T) {
	data, code, err := parseEnvelope([]byte(`{"result":"success","data":{"id":"01J"}}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(code, ""))
	qt.Assert(t, qt.Equals(string(data), `{"id":"01J"}`))
}

func TestParseEnvelopeError(t *testing.T) {
	_, code, err := parseEnvelope([]byte(`{"result":"error","code":"registry:not_found","message":"unknown client"}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(code, "registry:not_found"))
}

func TestParseEnvelopeGarbage(t *testing.T) {
	_, _, err := parseEnvelope([]byte(`not json`))
	qt.Assert(t, qt.IsNotNil(err))
}

// TestParseEnvelopeUnknownResult covers parseEnvelope's default branch: a
// "result" that is neither "success" nor "error" is malformed and must
// error, not silently succeed with no data (fail-closed).
func TestParseEnvelopeUnknownResult(t *testing.T) {
	_, _, err := parseEnvelope([]byte(`{"result":"weird"}`))
	qt.Assert(t, qt.IsNotNil(err))
}

// resultError bridges the DB house-style code (<domain>:<reason>) onto the
// kit taxonomy (err:<domain>:<reason>) so FromResultCode maps status
// correctly, for BOTH domains this service produces (registry:* and
// audit:*). not_found is a builtin kit reason (-> 404); illegal_transition is
// registered by app.go as "illegal-transition" (-> 409, same convention as
// the session service's "not-cancellable").
func TestResultErrorHTTPStatus(t *testing.T) {
	qt.Assert(t, qt.Equals(mustStatus(t, resultError("registry:not_found")), 404))
	qt.Assert(t, qt.Equals(mustStatus(t, resultError("registry:illegal_transition")), 409))
	qt.Assert(t, qt.Equals(mustStatus(t, resultError("audit:not_found")), 404))

	invStatus := mustStatus(t, resultError("registry:invalid"))
	qt.Assert(t, qt.IsTrue(invStatus >= 400 && invStatus < 500))

	auditInvStatus := mustStatus(t, resultError("audit:invalid"))
	qt.Assert(t, qt.IsTrue(auditInvStatus >= 400 && auditInvStatus < 500))

	// Unregistered reasons fall through to InternalError (500) — never leak
	// raw DB text to the caller.
	qt.Assert(t, qt.Equals(mustStatus(t, resultError("registry:error")), 500))
	qt.Assert(t, qt.Equals(mustStatus(t, resultError("audit:error")), 500))

	qt.Assert(t, qt.IsNil(resultError("")))
}

// TestRegisteredCredentialJSONMatchesWP10Golden pins IntendedUse/
// RegisteredCredentialJSON's JSON shape against a golden fixture. The two
// types are independently defined in TWO modules (the session service's
// internal/registrydb and this package) because that registrydb is internal
// to its own module and cannot be imported here (see repo.go's package-level
// NOTE) — the ONLY thing keeping them from silently drifting apart is that
// both sides serialize to byte-identical JSON. The golden below is the
// canonical shape; if this test and the session service's mirror test (its
// own copy of this same golden) ever disagree, the JSON shape broke — NOT
// just a cosmetic Go-side rename — since a client's intended_use.credentials
// rows written by one service must decode correctly when read by the other
// (dcql.WithinScope's scope-projection).
func TestRegisteredCredentialJSONMatchesWP10Golden(t *testing.T) {
	const golden = `{"id":"01JGOLDENINTENDEDUSE00000","intended_use_id":"iu-golden","purpose":["age verification"],"credentials":[{"format":"mso_mdoc","doctypes_or_vcts":["eu.europa.ec.eudi.pid.1"],"all_claims":false,"claims":[["age_over_18"],["nationality"]]},{"format":"dc+sd-jwt","doctypes_or_vcts":["urn:eudi:pid:1"],"all_claims":true}]}`

	fixture := IntendedUse{
		ID:            "01JGOLDENINTENDEDUSE00000",
		IntendedUseID: "iu-golden",
		Purpose:       json.RawMessage(`["age verification"]`),
		Credentials: []RegisteredCredentialJSON{
			{
				Format:         "mso_mdoc",
				DoctypesOrVCTs: []string{"eu.europa.ec.eudi.pid.1"},
				AllClaims:      false,
				Claims:         [][]any{{"age_over_18"}, {"nationality"}},
			},
			{
				Format:         "dc+sd-jwt",
				DoctypesOrVCTs: []string{"urn:eudi:pid:1"},
				AllClaims:      true,
			},
		},
	}

	got, err := json.Marshal(fixture)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(got), golden))

	// Round-trip: the golden JSON decodes back into the identical fixture —
	// proves the shape is symmetric, not just an accidental one-way match.
	var decoded IntendedUse
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(golden), &decoded)))
	qt.Assert(t, qt.DeepEquals(decoded, fixture))
}

func seedDraftClient(t *testing.T, f *Fake, name, email string) string {
	t.Helper()
	id, err := f.CreateDraftClient(t.Context(), name, email, "unit-test")
	qt.Assert(t, qt.IsNil(err))
	return id
}

// TestTransitionMatrix is the Go table test for the transition matrix
// (illegal transitions rejected), mirroring the SQL-side coverage.
// TestSetClientStatus is a Fake-only test seam (see fake.go) letting each
// case start from an arbitrary state without walking the whole chain.
func TestTransitionMatrix(t *testing.T) {
	legal := [][2]string{
		{"draft", "evidence_submitted"},
		{"evidence_submitted", "filed_with_registrar"},
		{"filed_with_registrar", "registered"},
		{"registered", "active"},
		{"active", "suspended"},
		{"suspended", "active"},
		{"suspended", "offboarded"},
		{"active", "offboarded"},
	}
	illegal := [][2]string{
		{"draft", "active"},
		{"draft", "registered"},
		{"draft", "offboarded"},
		{"evidence_submitted", "registered"},
		{"evidence_submitted", "active"},
		{"active", "registered"},
		{"active", "evidence_submitted"},
		{"registered", "suspended"},
		{"offboarded", "active"},
		{"offboarded", "draft"},
		{"suspended", "filed_with_registrar"},
	}

	for _, edge := range legal {
		from, to := edge[0], edge[1]
		t.Run("legal_"+from+"_to_"+to, func(t *testing.T) {
			f := NewFake()
			id := seedDraftClient(t, f, "Client", "")
			f.TestSetClientStatus(id, from)

			err := f.TransitionClient(t.Context(), id, to, "operator-1", "ev-ref", "because")
			qt.Assert(t, qt.IsNil(err))

			c, err := f.GetClientFull(t.Context(), id)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(c.Status, to))

			// audited atomically with the flip (who/when/evidence ref).
			entries := f.AuditLog()
			last := entries[len(entries)-1]
			qt.Assert(t, qt.Equals(last.ClientID, id))
			qt.Assert(t, qt.Equals(last.Action, "client.transition"))
			qt.Assert(t, qt.Equals(last.Actor, "operator-1"))
			var detail struct {
				From        string `json:"from"`
				To          string `json:"to"`
				EvidenceRef string `json:"evidence_ref"`
				Reason      string `json:"reason"`
			}
			qt.Assert(t, qt.IsNil(json.Unmarshal(last.Detail, &detail)))
			qt.Assert(t, qt.Equals(detail.From, from))
			qt.Assert(t, qt.Equals(detail.To, to))
			qt.Assert(t, qt.Equals(detail.EvidenceRef, "ev-ref"))
			qt.Assert(t, qt.Equals(detail.Reason, "because"))
		})
	}

	for _, edge := range illegal {
		from, to := edge[0], edge[1]
		t.Run("illegal_"+from+"_to_"+to, func(t *testing.T) {
			f := NewFake()
			id := seedDraftClient(t, f, "Client", "")
			f.TestSetClientStatus(id, from)
			preCount := len(f.AuditLog())

			err := f.TransitionClient(t.Context(), id, to, "operator-1", "", "")
			qt.Assert(t, qt.Equals(mustStatus(t, err), 409))

			// No partial write: status unchanged, no audit row appended.
			c, gerr := f.GetClientFull(t.Context(), id)
			qt.Assert(t, qt.IsNil(gerr))
			qt.Assert(t, qt.Equals(c.Status, from))
			qt.Assert(t, qt.HasLen(f.AuditLog(), preCount))
		})
	}
}

func TestTransitionClientUnknownID(t *testing.T) {
	f := NewFake()
	err := f.TransitionClient(t.Context(), "no-such-client", "active", "actor", "", "")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 404))
}

// TestCreateDraftClientSeedsStatusAndContactEmails covers CreateDraftClient +
// GetClientFull (both still-live methods): a freshly created draft client
// starts in status "draft" and carries through the seeded contact email.
func TestCreateDraftClientSeedsStatusAndContactEmails(t *testing.T) {
	f := NewFake()
	id := seedDraftClient(t, f, "Acme", "ops@acme.example")

	c, err := f.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.Status, "draft"))
	qt.Assert(t, qt.DeepEquals(c.ContactEmails, []string{"ops@acme.example"}))
}

// TestCreateDraftClientGeneratesSlug is the Go-side coverage (mirroring the
// SQL-side assertions of the same behavior): CreateDraftClient auto-generates
// a non-empty slug — the registry.client.slug column is live — and two
// clients registered with the EXACT SAME name get DISTINCT slugs
// (collision-safety from the per-row id-derived suffix, not the slugified
// name alone).
func TestCreateDraftClientGeneratesSlug(t *testing.T) {
	f := NewFake()
	id1 := seedDraftClient(t, f, "Acme Corp", "")
	id2 := seedDraftClient(t, f, "Acme Corp", "")
	qt.Assert(t, qt.Not(qt.Equals(id1, id2)))

	c1, err := f.GetClientFull(t.Context(), id1)
	qt.Assert(t, qt.IsNil(err))
	c2, err := f.GetClientFull(t.Context(), id2)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.Not(qt.Equals(c1.Slug, "")))
	qt.Assert(t, qt.Not(qt.Equals(c2.Slug, "")))
	qt.Check(t, qt.Not(qt.Equals(c1.Slug, c2.Slug)))
}

// TestSetClientRegistrarIdentity covers that registry_uri/client_identifier
// start empty (create_draft_client's seed — see that procedure's doc comment)
// and SetClientRegistrarIdentity is the real (audited) Store method that
// populates them, distinct from the pre-existing TestSetClientRegistrarIdentity
// test-only bypass ts5check's own fixtures use.
func TestSetClientRegistrarIdentity(t *testing.T) {
	f := NewFake()
	id := seedDraftClient(t, f, "Acme", "")

	c, err := f.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.RegistryURI, ""))
	qt.Assert(t, qt.Equals(c.ClientIdentifier, ""))

	err = f.SetClientRegistrarIdentity(t.Context(), id, "https://registrar.example-ms.eu", "DEUTR.HRB123456", "operator-1")
	qt.Assert(t, qt.IsNil(err))

	c, err = f.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.RegistryURI, "https://registrar.example-ms.eu"))
	qt.Assert(t, qt.Equals(c.ClientIdentifier, "DEUTR.HRB123456"))

	// audited atomically with the write.
	entries := f.AuditLog()
	last := entries[len(entries)-1]
	qt.Assert(t, qt.Equals(last.ClientID, id))
	qt.Assert(t, qt.Equals(last.Action, "client.set_registrar_identity"))
	qt.Assert(t, qt.Equals(last.Actor, "operator-1"))

	// unknown client -> not_found.
	err = f.SetClientRegistrarIdentity(t.Context(), "no-such-client", "https://x", "y", "operator-1")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 404))
}

// TestSetClientWebhook covers that default_webhook_url starts empty
// (create_draft_client's seed) and SetClientWebhook is the real (audited)
// Store method that populates it — the setter this service's ARF TS7 deletion
// webhook AND the session service's session-result webhook both need before
// either can ever reach a real client.
func TestSetClientWebhook(t *testing.T) {
	f := NewFake()
	id := seedDraftClient(t, f, "Acme", "")

	c, err := f.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.DefaultWebhook, ""))

	err = f.SetClientWebhook(t.Context(), id, "https://example.com/webhooks/eudi", "operator-1")
	qt.Assert(t, qt.IsNil(err))

	c, err = f.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.DefaultWebhook, "https://example.com/webhooks/eudi"))

	// audited atomically with the write.
	entries := f.AuditLog()
	last := entries[len(entries)-1]
	qt.Assert(t, qt.Equals(last.ClientID, id))
	qt.Assert(t, qt.Equals(last.Action, "client.set_webhook"))
	qt.Assert(t, qt.Equals(last.Actor, "operator-1"))

	// unknown client -> not_found.
	err = f.SetClientWebhook(t.Context(), "no-such-client", "https://example.com/x", "operator-1")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 404))
}

// TestSetClientWebhookRejectsNonHTTPSOrRelativeURL is the acceptance test:
// "a non-https or relative URL is rejected".
func TestSetClientWebhookRejectsNonHTTPSOrRelativeURL(t *testing.T) {
	f := NewFake()
	id := seedDraftClient(t, f, "Acme", "")

	for _, bad := range []string{
		"http://example.com/webhooks/eudi", // not https
		"/webhooks/eudi",                   // relative
		"ftp://example.com/x",              // wrong scheme
		"",                                 // empty
		"https://",                         // no host
		"not-a-url at all",
	} {
		err := f.SetClientWebhook(t.Context(), id, bad, "operator-1")
		qt.Assert(t, qt.Equals(mustStatus(t, err), 400), qt.Commentf("expected 400 for webhook_url=%q", bad))

		c, getErr := f.GetClientFull(t.Context(), id)
		qt.Assert(t, qt.IsNil(getErr))
		qt.Check(t, qt.Equals(c.DefaultWebhook, ""), qt.Commentf("webhook_url=%q must not have been persisted", bad))
	}
}

func TestListClientsByState(t *testing.T) {
	f := NewFake()
	a := seedDraftClient(t, f, "A", "")
	b := seedDraftClient(t, f, "B", "")
	f.TestSetClientStatus(b, "active")

	grouped, err := f.ListClientsByState(t.Context())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(grouped["draft"], 1))
	qt.Assert(t, qt.Equals(grouped["draft"][0].ID, a))
	qt.Assert(t, qt.HasLen(grouped["active"], 1))
	qt.Assert(t, qt.Equals(grouped["active"][0].ID, b))
}

func TestSaveWRPDocumentReplacesIntendedUses(t *testing.T) {
	f := NewFake()
	id := seedDraftClient(t, f, "Acme", "")

	doc := json.RawMessage(`{"legalPerson":{}}`)
	err := f.SaveWRPDocument(t.Context(), id, doc, []IntendedUse{
		{IntendedUseID: "iu-1", Credentials: []RegisteredCredentialJSON{{Format: "mso_mdoc", AllClaims: true}}},
		{IntendedUseID: "iu-2"},
	}, "actor-1")
	qt.Assert(t, qt.IsNil(err))

	c, err := f.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(c.WRPDocument), string(doc)))

	// Replace-all: a second save with only "iu-1" drops "iu-2".
	err = f.SaveWRPDocument(t.Context(), id, doc, []IntendedUse{{IntendedUseID: "iu-1"}}, "actor-1")
	qt.Assert(t, qt.IsNil(err))

	// unknown client -> not_found
	err = f.SaveWRPDocument(t.Context(), "no-such-client", doc, nil, "actor-1")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 404))
}

// TestListIntendedUses covers ListIntendedUses (the read path the lifecycle
// service's "-> active" precondition needs): SaveWRPDocument's projections
// read back exactly, an unknown client yields an empty slice (not an error —
// matches the underlying procedure's own documented behavior, a list read
// rather than a single-resource lookup).
func TestListIntendedUses(t *testing.T) {
	f := NewFake()
	id := seedDraftClient(t, f, "Acme", "")

	err := f.SaveWRPDocument(t.Context(), id, json.RawMessage(`{}`), []IntendedUse{
		{IntendedUseID: "iu-1", Credentials: []RegisteredCredentialJSON{{Format: "mso_mdoc", AllClaims: true}}},
		{IntendedUseID: "iu-2", RevokedAt: "2026-01-01"},
	}, "actor-1")
	qt.Assert(t, qt.IsNil(err))

	ius, err := f.ListIntendedUses(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(ius, 2))
	qt.Assert(t, qt.Equals(ius[0].IntendedUseID, "iu-1"))
	qt.Assert(t, qt.Equals(ius[0].RevokedAt, ""))
	qt.Assert(t, qt.Equals(ius[1].IntendedUseID, "iu-2"))
	qt.Assert(t, qt.Equals(ius[1].RevokedAt, "2026-01-01"))

	ius, err = f.ListIntendedUses(t.Context(), "no-such-client")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(ius, 0))
}

// TestListIntendedUsesOrdersByInsertionNotLexicographically asserts
// registry.list_intended_uses orders "by iu.created_at" (insertion order),
// NOT by intended_use_id — the Fake must match. "iu-z" registered before
// "iu-a" must still list before it; a
// second SaveWRPDocument call that adds "iu-m" must append it at the end
// (its first-seen position) while the first two KEEP their original
// relative order, mirroring the real procedure's upsert (which never
// touches an existing row's created_at).
func TestListIntendedUsesOrdersByInsertionNotLexicographically(t *testing.T) {
	f := NewFake()
	id := seedDraftClient(t, f, "Acme", "")

	err := f.SaveWRPDocument(t.Context(), id, json.RawMessage(`{}`), []IntendedUse{
		{IntendedUseID: "iu-z"},
		{IntendedUseID: "iu-a"},
	}, "actor-1")
	qt.Assert(t, qt.IsNil(err))

	ius, err := f.ListIntendedUses(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(ius, 2))
	qt.Assert(t, qt.Equals(ius[0].IntendedUseID, "iu-z")) // first-seen, despite sorting after "iu-a"
	qt.Assert(t, qt.Equals(ius[1].IntendedUseID, "iu-a"))

	// A second save keeps both existing ids (re-listed in the same call, in
	// reverse) and adds a brand-new one.
	err = f.SaveWRPDocument(t.Context(), id, json.RawMessage(`{}`), []IntendedUse{
		{IntendedUseID: "iu-a"},
		{IntendedUseID: "iu-z"},
		{IntendedUseID: "iu-m"},
	}, "actor-1")
	qt.Assert(t, qt.IsNil(err))

	ius, err = f.ListIntendedUses(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(ius, 3))
	qt.Assert(t, qt.Equals(ius[0].IntendedUseID, "iu-z")) // unchanged relative order
	qt.Assert(t, qt.Equals(ius[1].IntendedUseID, "iu-a"))
	qt.Assert(t, qt.Equals(ius[2].IntendedUseID, "iu-m")) // new id appended at the end
}

// TestSetIntendedUsesReplacesIdentifier is the filing-confirmation acceptance
// at the Store layer: SetIntendedUses (unlike SaveWRPDocument,
// its wizard-facing sibling) is the path filing confirmation uses to
// replace a pending-<ulid> IntendedUseID with a registrar-assigned one —
// the OTHER fields (Purpose/Credentials) survive the replace unchanged, the
// old identifier is gone from the list (replace-all, not append), and the
// write is audited. (The row's internal ID is NOT expected to survive a
// rename — see replaceIntendedUsesLocked's doc comment for why that
// mirrors, not diverges from, the real registry.set_intended_uses
// procedure; the internal ID is never exposed to any route/handler logic
// either way.)
func TestSetIntendedUsesReplacesIdentifier(t *testing.T) {
	f := NewFake()
	id := seedDraftClient(t, f, "Acme", "")

	err := f.SaveWRPDocument(t.Context(), id, json.RawMessage(`{}`), []IntendedUse{
		{IntendedUseID: "pending-aaa", Purpose: json.RawMessage(`[{"lang":"en","content":"identification"}]`)},
	}, "actor-1")
	qt.Assert(t, qt.IsNil(err))

	before, err := f.ListIntendedUses(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(before, 1))

	replaced := before[0]
	replaced.IntendedUseID = "NL-REG-0001"
	replaced.ID = "" // the caller never knows/sends the internal id
	err = f.SetIntendedUses(t.Context(), id, []IntendedUse{replaced}, "actor-2")
	qt.Assert(t, qt.IsNil(err))

	after, err := f.ListIntendedUses(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(after, 1)) // replace-all: the old "pending-aaa" identifier is gone, not appended alongside
	qt.Check(t, qt.Equals(after[0].IntendedUseID, "NL-REG-0001"))
	qt.Check(t, qt.StringContains(string(after[0].Purpose), "identification"))

	// Audited via a SEPARATE entry (Store interface doc comment: not atomic
	// with the replace) rather than folded into client.save_wrp_document.
	entries := f.AuditLog()
	last := entries[len(entries)-1]
	qt.Check(t, qt.Equals(last.Action, "client.set_intended_uses"))
	qt.Check(t, qt.Equals(last.Actor, "actor-2"))
}

// TestSetIntendedUsesUnknownClientNotFound / TestSetIntendedUsesEmptyIdentifierInvalid
// mirror SaveWRPDocument's own validation (same replace-all contract).
func TestSetIntendedUsesUnknownClientNotFound(t *testing.T) {
	f := NewFake()
	err := f.SetIntendedUses(t.Context(), "no-such-client", []IntendedUse{{IntendedUseID: "x"}}, "actor-1")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 404))
}

func TestSetIntendedUsesEmptyIdentifierInvalid(t *testing.T) {
	f := NewFake()
	id := seedDraftClient(t, f, "Acme", "")
	err := f.SetIntendedUses(t.Context(), id, []IntendedUse{{IntendedUseID: ""}}, "actor-1")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 400))
}

func TestEvidenceLifecycleAndOwnership(t *testing.T) {
	f := NewFake()
	clientA := seedDraftClient(t, f, "A", "")
	clientB := seedDraftClient(t, f, "B", "")

	e := &Evidence{Filename: "contract.pdf", Mime: "application/pdf", SHA256: "abc", SizeBytes: 5}
	id, err := f.AddEvidence(t.Context(), clientA, e, []byte("hello"), "actor-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, e.ID))

	content, mime, err := f.GetEvidenceContent(t.Context(), clientA, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(content), "hello"))
	qt.Assert(t, qt.Equals(mime, "application/pdf"))

	// cross-client read -> not_found
	_, _, err = f.GetEvidenceContent(t.Context(), clientB, id)
	qt.Assert(t, qt.Equals(mustStatus(t, err), 404))

	list, err := f.ListEvidence(t.Context(), clientA)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(list, 1))
	qt.Assert(t, qt.Equals(list[0].Filename, "contract.pdf"))
}

func TestAppendAuditAndDeletionLog(t *testing.T) {
	f := NewFake()
	clientA := seedDraftClient(t, f, "A", "")

	err := f.AppendAudit(t.Context(), "actor-1", clientA, "custom.action", json.RawMessage(`{"k":"v"}`))
	qt.Assert(t, qt.IsNil(err))
	entries := f.AuditLog()
	qt.Assert(t, qt.Equals(entries[len(entries)-1].Action, "custom.action"))

	id, err := f.LogDeletionRequest(t.Context(), clientA, "sess-1", []string{"given_name", "family_name"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(id != ""))

	reqs, err := f.ListDeletionRequests(t.Context(), clientA, 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(reqs, 1))
	qt.Assert(t, qt.DeepEquals(reqs[0].AttributeNames, []string{"given_name", "family_name"}))

	// scoped: another client sees none of it.
	reqsB, err := f.ListDeletionRequests(t.Context(), "no-such-client", 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(reqsB, 0))
}

// TestListAuditEntries covers append-then-list: rows come back newest-first,
// scoped to clientID (the operator client-detail page's "audit trail"
// acceptance, backed by the fake store).
func TestListAuditEntries(t *testing.T) {
	f := NewFake()
	clientA := seedDraftClient(t, f, "A", "") // audits 'client.create'
	clientB := seedDraftClient(t, f, "B", "")

	err := f.AppendAudit(t.Context(), "actor-1", clientA, "custom.action.one", json.RawMessage(`{"k":1}`))
	qt.Assert(t, qt.IsNil(err))
	err = f.AppendAudit(t.Context(), "actor-1", clientA, "custom.action.two", json.RawMessage(`{"k":2}`))
	qt.Assert(t, qt.IsNil(err))

	entries, err := f.ListAuditEntries(t.Context(), clientA, 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(entries, 3)) // client.create + the two custom appends
	// newest first.
	qt.Assert(t, qt.Equals(entries[0].Action, "custom.action.two"))
	qt.Assert(t, qt.Equals(entries[1].Action, "custom.action.one"))
	qt.Assert(t, qt.Equals(entries[2].Action, "client.create"))
	for _, e := range entries {
		qt.Check(t, qt.Equals(e.ClientID, clientA))
		qt.Check(t, qt.IsTrue(e.ID != ""))
		qt.Check(t, qt.IsFalse(e.At.IsZero()))
	}

	// limit is honored.
	limited, err := f.ListAuditEntries(t.Context(), clientA, 1)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(limited, 1))
	qt.Assert(t, qt.Equals(limited[0].Action, "custom.action.two"))

	// scoped: another client sees only its own entry.
	entriesB, err := f.ListAuditEntries(t.Context(), clientB, 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(entriesB, 1))
	qt.Assert(t, qt.Equals(entriesB[0].ClientID, clientB))
}

// TestLogDeletionRequestAcceptsNilAttributeNames is a Fake-vs-SQL parity
// check: PG.LogDeletionRequest (repo.go) converts a nil attributeNames slice
// to []string{} before calling
// audit.log_deletion_request, and the SQL procedure only rejects a MISSING
// attribute_names key (pi_data->'attribute_names' is null), never an empty
// array — so a nil slice must succeed on the Fake exactly as it does against
// the real DB, not be rejected as audit:invalid.
func TestLogDeletionRequestAcceptsNilAttributeNames(t *testing.T) {
	f := NewFake()
	clientA := seedDraftClient(t, f, "A", "")

	id, err := f.LogDeletionRequest(t.Context(), clientA, "sess-nil", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(id != ""))

	reqs, err := f.ListDeletionRequests(t.Context(), clientA, 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(reqs, 1))
	qt.Assert(t, qt.HasLen(reqs[0].AttributeNames, 0))
}

func TestPurgeOffboarded(t *testing.T) {
	f := NewFake()
	clientA := seedDraftClient(t, f, "A", "")

	// Pattern A guard: not yet offboarded -> registry:invalid.
	err := f.PurgeOffboarded(t.Context(), clientA, "actor-1")
	invStatus := mustStatus(t, err)
	qt.Assert(t, qt.IsTrue(invStatus >= 400 && invStatus < 500))

	e := &Evidence{Filename: "contract.pdf", Mime: "application/pdf", SHA256: "abc", SizeBytes: 5}
	_, err = f.AddEvidence(t.Context(), clientA, e, []byte("hello"), "actor-1")
	qt.Assert(t, qt.IsNil(err))

	f.TestSetClientStatus(clientA, "offboarded")
	err = f.PurgeOffboarded(t.Context(), clientA, "actor-1")
	qt.Assert(t, qt.IsNil(err))

	// content purged, metadata retained.
	content, _, err := f.GetEvidenceContent(t.Context(), clientA, e.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(content, 0))
	list, err := f.ListEvidence(t.Context(), clientA)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(list, 1))
	qt.Assert(t, qt.Equals(list[0].Filename, "contract.pdf"))

	entries := f.AuditLog()
	qt.Assert(t, qt.Equals(entries[len(entries)-1].Action, "client.purge"))
}
