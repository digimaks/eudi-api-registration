package registrydb_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/digimaks/eudi-api-registration/internal/registrydb"

	"github.com/go-quicktest/qt"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testStore requires the compose dev stack with migrations applied
// (util -> registry -> session -> audit). It connects as
// registration_api_public, the SAME EXECUTE-only role production uses — never
// the owner.
func testStore(t *testing.T) registrydb.Store {
	t.Helper()
	dsn := os.Getenv("EUDI_API_REGISTRATION_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set EUDI_API_REGISTRATION_TEST_PG_DSN (compose dev stack) for integration run")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(pool.Close)
	return registrydb.NewPG(pool)
}

func uniqueName(t *testing.T, label string) string {
	t.Helper()
	return fmt.Sprintf("%s-%s-%d", t.Name(), label, time.Now().UnixNano())
}

type statusCoder interface{ StatusCode() int }

func TestProcedureLifecycleRoundtrip(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	clientID, err := store.CreateDraftClient(ctx, uniqueName(t, "client"), "ops@example.test", "integration-test")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(clientID), 26)) // ULID

	c, err := store.GetClientFull(ctx, clientID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.Status, "draft"))

	// legal walk through the whole state machine.
	for _, to := range []string{"evidence_submitted", "filed_with_registrar", "registered", "active"} {
		qt.Assert(t, qt.IsNil(store.TransitionClient(ctx, clientID, to, "integration-test", "", "")))
	}
	c, err = store.GetClientFull(ctx, clientID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.Status, "active"))

	// illegal edge -> 409 (err:registry:illegal_transition, once registered
	// by app.go in the real service — this test relies on the SAME
	// RegisterReason call repo_test.go's init() makes, since this binary
	// doesn't run app.go's init either).
	err = store.TransitionClient(ctx, clientID, "registered", "integration-test", "", "")
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 409))

	// unknown client -> 404
	_, err = store.GetClientFull(ctx, "01JZXNOSUCHCLIENT00000000")
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok = err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))
}

// TestProcedureEvidenceRoundtrip covers registry.add_evidence /
// registry.get_evidence_content against the REAL procedures. These are NOT
// dead code — PurgeOffboarded (the live "-> offboarded" side effect,
// internal/lifecycle.Service.Transition) purges evidence blob content for the
// offboarded client, so live-procedure coverage for how evidence rows
// actually get created/read stays valuable.
func TestProcedureEvidenceRoundtrip(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	clientID, err := store.CreateDraftClient(ctx, uniqueName(t, "client"), "", "integration-test")
	qt.Assert(t, qt.IsNil(err))

	evidence := &registrydb.Evidence{Filename: "contract.pdf", Mime: "application/pdf", SHA256: "abc123", SizeBytes: 5}
	evidenceID, err := store.AddEvidence(ctx, clientID, evidence, []byte("hello"), "integration-test")
	qt.Assert(t, qt.IsNil(err))

	content, mime, err := store.GetEvidenceContent(ctx, clientID, evidenceID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(content), "hello"))
	qt.Assert(t, qt.Equals(mime, "application/pdf"))
}

func TestProcedureSaveWRPDocumentAndAudit(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	clientID, err := store.CreateDraftClient(ctx, uniqueName(t, "client"), "", "integration-test")
	qt.Assert(t, qt.IsNil(err))

	doc := json.RawMessage(`{"legalPerson":{}}`)
	err = store.SaveWRPDocument(ctx, clientID, doc, []registrydb.IntendedUse{
		{IntendedUseID: "iu-1", Credentials: []registrydb.RegisteredCredentialJSON{
			{Format: "mso_mdoc", DoctypesOrVCTs: []string{"eu.europa.ec.eudi.pid.1"}, AllClaims: true},
		}},
	}, "integration-test")
	qt.Assert(t, qt.IsNil(err))

	c, err := store.GetClientFull(ctx, clientID)
	qt.Assert(t, qt.IsNil(err))
	// NOTE: jsonb round-trips through Postgres re-serialized (it normalizes
	// whitespace, e.g. adds a space after ':'/',' ) — compare parsed JSON, not
	// raw bytes. This is true of any jsonb column, not specific to this one.
	qt.Assert(t, qt.JSONEquals([]byte(c.WRPDocument), map[string]any{"legalPerson": map[string]any{}}))

	qt.Assert(t, qt.IsNil(store.AppendAudit(ctx, "integration-test", clientID, "custom.action", json.RawMessage(`{"k":"v"}`))))

	id, err := store.LogDeletionRequest(ctx, clientID, "sess-integration-1", []string{"given_name"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(id != ""))

	reqs, err := store.ListDeletionRequests(ctx, clientID, 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(reqs, 1))
}

// TestProcedureListIntendedUsesAndAuditEntries covers ListIntendedUses and
// ListAuditEntries against the REAL procedures (not just the Fake):
// ListIntendedUses (the "-> active" activation precondition's read path —
// registry.list_intended_uses, reused here with a registration_api_public
// grant) and ListAuditEntries (audit.list_entries — the operator
// client-detail page's "audit trail" read path).
func TestProcedureListIntendedUsesAndAuditEntries(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	clientID, err := store.CreateDraftClient(ctx, uniqueName(t, "client"), "", "integration-test")
	qt.Assert(t, qt.IsNil(err))

	// ListIntendedUses: unknown client -> empty slice, not an error.
	ius, err := store.ListIntendedUses(ctx, "01JZXNOSUCHCLIENT00000000")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(ius, 0))

	err = store.SaveWRPDocument(ctx, clientID, json.RawMessage(`{}`), []registrydb.IntendedUse{
		{IntendedUseID: "iu-1"},
		{IntendedUseID: "iu-2", RevokedAt: "2026-01-01"},
	}, "integration-test")
	qt.Assert(t, qt.IsNil(err))

	ius, err = store.ListIntendedUses(ctx, clientID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(ius, 2))

	// ListAuditEntries: newest first, scoped to clientID. CreateDraftClient +
	// SaveWRPDocument each self-audit atomically, so there are already 2
	// entries before any explicit AppendAudit call.
	qt.Assert(t, qt.IsNil(store.AppendAudit(ctx, "integration-test", clientID, "custom.integration.action", json.RawMessage(`{"k":"v"}`))))

	entries, err := store.ListAuditEntries(ctx, clientID, 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(entries, 3))
	qt.Assert(t, qt.Equals(entries[0].Action, "custom.integration.action")) // most recent
	qt.Assert(t, qt.Equals(entries[0].ClientID, clientID))

	limited, err := store.ListAuditEntries(ctx, clientID, 1)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(limited, 1))

	// scoped: an unrelated client sees none of it.
	otherID, err := store.CreateDraftClient(ctx, uniqueName(t, "other"), "", "integration-test")
	qt.Assert(t, qt.IsNil(err))
	otherEntries, err := store.ListAuditEntries(ctx, otherID, 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(otherEntries, 1)) // just its own 'client.create'
}

// TestProcedureSetClientRegistrarIdentity is live-Postgres coverage for
// registry.set_client_registrar_identity — the Go bridge
// (registrydb.Store.SetClientRegistrarIdentity), not just the SQL-level unit
// tests, against the real registration_api_public-EXECUTE-only role.
func TestProcedureSetClientRegistrarIdentity(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	clientID, err := store.CreateDraftClient(ctx, uniqueName(t, "client"), "", "integration-test")
	qt.Assert(t, qt.IsNil(err))

	c, err := store.GetClientFull(ctx, clientID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.RegistryURI, ""))
	qt.Assert(t, qt.Equals(c.ClientIdentifier, ""))

	err = store.SetClientRegistrarIdentity(ctx, clientID, "https://registrar.example-ms.eu", "DEUTR.HRB123456", "integration-test")
	qt.Assert(t, qt.IsNil(err))

	c, err = store.GetClientFull(ctx, clientID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.RegistryURI, "https://registrar.example-ms.eu"))
	qt.Assert(t, qt.Equals(c.ClientIdentifier, "DEUTR.HRB123456"))

	// audited.
	entries, err := store.ListAuditEntries(ctx, clientID, 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(entries[0].Action, "client.set_registrar_identity"))

	// unknown client -> 404.
	err = store.SetClientRegistrarIdentity(ctx, "01JZXNOSUCHCLIENT00000000", "https://x", "y", "integration-test")
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))
}

// TestProcedureSetClientWebhook is live-Postgres coverage for
// registry.set_client_webhook — the Go bridge
// (registrydb.Store.SetClientWebhook), not just the SQL-level unit tests or
// the Fake, against the real registration_api_public-EXECUTE-only role.
func TestProcedureSetClientWebhook(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	clientID, err := store.CreateDraftClient(ctx, uniqueName(t, "client"), "", "integration-test")
	qt.Assert(t, qt.IsNil(err))

	c, err := store.GetClientFull(ctx, clientID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.DefaultWebhook, ""))

	err = store.SetClientWebhook(ctx, clientID, "https://example.test/webhooks/eudi", "integration-test")
	qt.Assert(t, qt.IsNil(err))

	c, err = store.GetClientFull(ctx, clientID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.DefaultWebhook, "https://example.test/webhooks/eudi"))

	// audited.
	entries, err := store.ListAuditEntries(ctx, clientID, 10)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(entries[0].Action, "client.set_webhook"))

	// non-https/relative URL -> the procedure's own registry:invalid (400),
	// not just the Fake's Go-side check.
	err = store.SetClientWebhook(ctx, clientID, "/relative/path", "integration-test")
	qt.Assert(t, qt.IsNotNil(err))
	sc2, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc2.StatusCode(), 400))

	// unknown client -> 404.
	err = store.SetClientWebhook(ctx, "01JZXNOSUCHCLIENT00000000", "https://example.test/x", "integration-test")
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))
}

// Mandatory role-leak test: registration_api_public has NO table access, and
// cannot mutate the append-only audit.entry even directly.
func TestRoleLeakDirectTableAccessFails(t *testing.T) {
	dsn := os.Getenv("EUDI_API_REGISTRATION_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set EUDI_API_REGISTRATION_TEST_PG_DSN (compose dev stack) for integration run")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(pool.Close)

	_, err = pool.Exec(context.Background(), "select * from registry.client limit 1")
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))
	_, err = pool.Exec(context.Background(), "select * from audit.entry limit 1")
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))
	_, err = pool.Exec(context.Background(),
		"insert into registry.client (name, registry_uri, client_identifier, default_webhook_url) values ('x','x','x','x')")
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))
}
