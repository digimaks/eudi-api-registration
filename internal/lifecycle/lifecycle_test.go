package lifecycle_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/go-quicktest/qt"

	"github.com/dativa-lv/eudi-api-registration/internal/lifecycle"
	"github.com/dativa-lv/eudi-api-registration/internal/registrydb"
)

// This test binary never runs eudiapiregistration's App.init (lifecycle can't
// import that package — it would be a layering cycle: eudiapiregistration's
// routes import lifecycle, not the reverse), so mirror the reason
// registrations app.go makes, exactly like registrydb/repo_test.go's own init()
// does for the same reason. Keep in sync with app.go.
func init() {
	pkerrors.RegisterReason("illegalTransition", pkerrors.ReasonSpec{Status: 409, Title: "Illegal client-lifecycle transition"})
	pkerrors.RegisterReason("intendedUseRequired", pkerrors.ReasonSpec{Status: 422, Title: "Intended use required"})
	pkerrors.RegisterReason("registrarIdentityRequired", pkerrors.ReasonSpec{Status: 422, Title: "Client registrar identity required"})
	pkerrors.RegisterReason("ts5CheckFailed", pkerrors.ReasonSpec{Status: 422, Title: "ARF TS5 verification check failed"})
}

type statusCoder interface{ StatusCode() int }

func mustStatus(t *testing.T, err error) int {
	t.Helper()
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	return sc.StatusCode()
}

// newClientWithIntendedUse seeds a draft client with one non-revoked
// intended use and a recorded registrar identity — the baseline every
// table-test case below starts from, so the "-> active" precondition never
// masks the store's own legal/illegal verdict (see
// TestTransitionMatrixThroughLifecycleService's doc comment).
func newClientWithIntendedUse(t *testing.T, f *registrydb.Fake) string {
	t.Helper()
	id, err := f.CreateDraftClient(t.Context(), "Client", "", "operator-1")
	qt.Assert(t, qt.IsNil(err))
	err = f.SaveWRPDocument(t.Context(), id, json.RawMessage(`{}`),
		[]registrydb.IntendedUse{{IntendedUseID: "iu-1"}}, "operator-1")
	qt.Assert(t, qt.IsNil(err))
	f.TestSetClientRegistrarIdentity(id, "https://registrar.test/api", "RP-000123")
	return id
}

// TestTransitionMatrixThroughLifecycleService is the "table over all edges"
// acceptance, run through lifecycle.Service instead of directly against
// registrydb.Store (registrydb/repo_test.go's TestTransitionMatrix already
// covers the store itself — this proves the wrapper passes every edge
// through unchanged). Every case seeds one non-revoked intended use
// UNCONDITIONALLY (including the illegal-edge cases that target "active",
// e.g. draft->active): that keeps the "-> active" activation precondition
// satisfied for every case here, so what actually gets exercised and
// asserted is purely the pass-through behavior (legal -> store flips the
// state; illegal -> the store's own err:registry:illegal_transition, 409,
// surfaces verbatim, no partial write). The precondition itself — active
// rejected WITHOUT a non-revoked intended use — is a separate, dedicated
// concern tested below (TestTransitionToActiveRequiresNonRevokedIntendedUse
// and friends), deliberately kept out of this table so the two concerns
// don't interact and shadow each other's expected status code.
func TestTransitionMatrixThroughLifecycleService(t *testing.T) {
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
			f := registrydb.NewFake()
			svc := lifecycle.NewService(f)
			id := newClientWithIntendedUse(t, f)
			f.TestSetClientStatus(id, from)

			err := svc.Transition(t.Context(), id, to, "operator-1", "ev-ref", "because")
			qt.Assert(t, qt.IsNil(err))

			c, err := f.GetClientFull(t.Context(), id)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(c.Status, to))
		})
	}

	for _, edge := range illegal {
		from, to := edge[0], edge[1]
		t.Run("illegal_"+from+"_to_"+to, func(t *testing.T) {
			f := registrydb.NewFake()
			svc := lifecycle.NewService(f)
			id := newClientWithIntendedUse(t, f)
			f.TestSetClientStatus(id, from)

			err := svc.Transition(t.Context(), id, to, "operator-1", "", "")
			qt.Assert(t, qt.Equals(mustStatus(t, err), 409))

			// No partial write: status unchanged.
			c, err := f.GetClientFull(t.Context(), id)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(c.Status, from))
		})
	}
}

// TestTransitionToOffboardedTriggersPurge is the "-> offboarded triggers
// purge" acceptance: after a successful "-> offboarded" edge,
// Store.PurgeOffboarded has actually run (evidence content zeroed; the
// purge itself is audited) — not just that the client's status flipped.
func TestTransitionToOffboardedTriggersPurge(t *testing.T) {
	f := registrydb.NewFake()
	svc := lifecycle.NewService(f)
	ctx := t.Context()

	id := newClientWithIntendedUse(t, f)
	f.TestSetClientStatus(id, "active")

	ev := &registrydb.Evidence{Filename: "contract.pdf", Mime: "application/pdf", SHA256: "abc123", SizeBytes: 3}
	evidenceID, err := f.AddEvidence(ctx, id, ev, []byte("pdf"), "operator-1")
	qt.Assert(t, qt.IsNil(err))

	err = svc.Transition(ctx, id, "offboarded", "operator-1", "", "closing down")
	qt.Assert(t, qt.IsNil(err))

	c, err := f.GetClientFull(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.Status, "offboarded"))

	content, _, err := f.GetEvidenceContent(ctx, id, evidenceID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(content), 0)) // purged: content zeroed, metadata retained

	entries := f.AuditLog()
	last := entries[len(entries)-1]
	qt.Assert(t, qt.Equals(last.Action, "client.purge"))
	qt.Assert(t, qt.Equals(last.ClientID, id))
}

// TestTransitionToActiveRequiresNonRevokedIntendedUse is the "-> active
// without intended uses rejected with a service-level error" acceptance: a
// client with ZERO intended uses can never reach "active",
// and the store is never even called (status stays "registered").
func TestTransitionToActiveRequiresNonRevokedIntendedUse(t *testing.T) {
	f := registrydb.NewFake()
	svc := lifecycle.NewService(f)
	ctx := t.Context()

	id, err := f.CreateDraftClient(ctx, "Client", "", "operator-1")
	qt.Assert(t, qt.IsNil(err))
	// The registrar identity is on file, so what this test exercises is the
	// intended-use half of the precondition alone.
	f.TestSetClientRegistrarIdentity(id, "https://registrar.test/api", "RP-000123")
	f.TestSetClientStatus(id, "registered")

	err = svc.Transition(ctx, id, "active", "operator-1", "", "")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 422))
	var p *pkerrors.Problem
	qt.Assert(t, qt.IsTrue(errors.As(err, &p)))
	qt.Check(t, qt.Equals(p.Code, "err:client:intendedUseRequired"))

	c, err := f.GetClientFull(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.Status, "registered")) // store never called
}

// TestTransitionToActiveRequiresRegistrarIdentity: a client with a non-revoked
// intended use but no usable registrar identity — the shape a client has when
// the dedicated registrar-identity call was skipped — is refused with the code
// that names the gap and the call that closes it; the store is never asked to
// flip the state. Every unusable shape is covered: never recorded, a registrar
// URL that is not an absolute https URL, and a missing identifier.
func TestTransitionToActiveRequiresRegistrarIdentity(t *testing.T) {
	for _, tc := range []struct{ name, registryURI, clientIdentifier string }{
		{"never recorded", "", ""},
		{"registrar URL not https", "http://registrar.test/api", "RP-000123"},
		{"registrar URL relative", "/ts5", "RP-000123"},
		{"identifier empty", "https://registrar.test/api", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := registrydb.NewFake()
			svc := lifecycle.NewService(f)
			ctx := t.Context()

			id, err := f.CreateDraftClient(ctx, "Client", "", "operator-1")
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.IsNil(f.SaveWRPDocument(ctx, id, json.RawMessage(`{}`),
				[]registrydb.IntendedUse{{IntendedUseID: "iu-1"}}, "operator-1")))
			f.TestSetClientRegistrarIdentity(id, tc.registryURI, tc.clientIdentifier)
			f.TestSetClientStatus(id, "registered")

			err = svc.Transition(ctx, id, "active", "operator-1", "", "")
			qt.Assert(t, qt.Equals(mustStatus(t, err), 422))
			var p *pkerrors.Problem
			qt.Assert(t, qt.IsTrue(errors.As(err, &p)))
			qt.Check(t, qt.Equals(p.Code, "err:client:registrarIdentityRequired"))
			qt.Check(t, qt.StringContains(p.Detail, "PUT /api/clients/{id}/registrar-identity"))

			c, err := f.GetClientFull(ctx, id)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(c.Status, "registered")) // store never called
		})
	}
}

// TestTransitionToActiveIllegalEdgeSurfacesIllegalTransitionNotIntendedUse
// verifies that an ILLEGAL edge into "active" — draft is not one of the two
// legal predecessors (registered, suspended) — must surface the store's own
// 409 err:registry:illegal_transition, NOT the service-level 422
// err:client:intendedUseRequired, even though this client also has zero
// intended uses. With an unconditional ordering (precondition checked for
// EVERY current status before ever calling Store.TransitionClient) this case
// would incorrectly return 422, masking the store's own illegal-transition
// verdict for this input class.
func TestTransitionToActiveIllegalEdgeSurfacesIllegalTransitionNotIntendedUse(t *testing.T) {
	f := registrydb.NewFake()
	svc := lifecycle.NewService(f)
	ctx := t.Context()

	id, err := f.CreateDraftClient(ctx, "Client", "", "operator-1")
	qt.Assert(t, qt.IsNil(err))
	// id stays "draft" (CreateDraftClient's default) and has ZERO intended
	// uses — draft->active is illegal regardless.

	err = svc.Transition(ctx, id, "active", "operator-1", "", "")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 409))

	c, err := f.GetClientFull(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.Status, "draft")) // no partial write
}

// TestTransitionToActiveRejectedWhenAllIntendedUsesRevoked: having intended
// uses on file is not enough — every one of them being revoked must reject
// activation exactly like having none at all.
func TestTransitionToActiveRejectedWhenAllIntendedUsesRevoked(t *testing.T) {
	f := registrydb.NewFake()
	svc := lifecycle.NewService(f)
	ctx := t.Context()

	id, err := f.CreateDraftClient(ctx, "Client", "", "operator-1")
	qt.Assert(t, qt.IsNil(err))
	err = f.SaveWRPDocument(ctx, id, json.RawMessage(`{}`),
		[]registrydb.IntendedUse{{IntendedUseID: "iu-1", RevokedAt: "2026-01-01"}}, "operator-1")
	qt.Assert(t, qt.IsNil(err))
	f.TestSetClientStatus(id, "registered")

	err = svc.Transition(ctx, id, "active", "operator-1", "", "")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 422))
}

// TestTransitionToActiveSucceedsWithNonRevokedIntendedUse: the mirror-image
// positive case — one non-revoked intended use is sufficient.
func TestTransitionToActiveSucceedsWithNonRevokedIntendedUse(t *testing.T) {
	f := registrydb.NewFake()
	svc := lifecycle.NewService(f)
	ctx := t.Context()

	id := newClientWithIntendedUse(t, f)
	f.TestSetClientStatus(id, "registered")

	err := svc.Transition(ctx, id, "active", "operator-1", "ev-ref", "verified")
	qt.Assert(t, qt.IsNil(err))

	c, err := f.GetClientFull(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.Status, "active"))
}

// TestTransitionToActiveBlockedByTS5Hook: the ARF TS5 seam actually gates
// activation once wired — even with a non-revoked intended use on file, a
// negative TS5OK result blocks "-> active" (a service-level 422, store never
// called).
func TestTransitionToActiveBlockedByTS5Hook(t *testing.T) {
	f := registrydb.NewFake()
	svc := lifecycle.NewService(f)
	svc.TS5OK = func(context.Context, string) bool { return false }
	ctx := t.Context()

	id := newClientWithIntendedUse(t, f)
	f.TestSetClientStatus(id, "registered")

	err := svc.Transition(ctx, id, "active", "operator-1", "", "")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 422))

	c, err := f.GetClientFull(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.Status, "registered"))
}

// TestNewServiceDefaultTS5OKIsPermissive: NewService's installed default
// must not itself block activation (the ARF TS5 check has not landed — this
// seam must be a no-op until it does).
func TestNewServiceDefaultTS5OKIsPermissive(t *testing.T) {
	svc := lifecycle.NewService(registrydb.NewFake())
	qt.Assert(t, qt.IsTrue(svc.TS5OK(t.Context(), "any-client")))
}

// TestTransitionToActiveUnknownClientSurfacesNotFound: an unknown clientID
// must surface the store's own not-found error, not be misread as "no
// intended uses" (registry.list_intended_uses returns an empty list for an
// unknown client too — see checkActivationPreconditions's doc comment).
func TestTransitionToActiveUnknownClientSurfacesNotFound(t *testing.T) {
	svc := lifecycle.NewService(registrydb.NewFake())
	err := svc.Transition(context.Background(), "no-such-client", "active", "operator-1", "", "")
	qt.Assert(t, qt.Equals(mustStatus(t, err), 404))
}

// errPurgeSimulated is the sentinel flakyPurgeStore returns for its injected
// PurgeOffboarded failures (TestOffboardPurgeIsRetriableAfterFailure).
var errPurgeSimulated = errors.New("simulated purge failure")

// flakyPurgeStore wraps a *registrydb.Fake and fails the next failNext calls
// to PurgeOffboarded with errPurgeSimulated instead of delegating to the
// real Fake — simulating a purge that fails right after a "-> offboarded"
// flip has already committed.
type flakyPurgeStore struct {
	*registrydb.Fake
	failNext int
}

func (s *flakyPurgeStore) PurgeOffboarded(ctx context.Context, clientID, actor string) error {
	if s.failNext > 0 {
		s.failNext--
		return errPurgeSimulated
	}
	return s.Fake.PurgeOffboarded(ctx, clientID, actor)
}

// TestOffboardPurgeIsRetriableAfterFailure verifies that when
// PurgeOffboarded fails right after the "-> offboarded" flip commits, the
// flip is NOT lost — offboarded is a terminal state and
// offboarded->offboarded is illegal, so a client stuck there with a failed
// purge must still be reachable by a retry. Re-submitting the same offboard
// action on the now-offboarded client must retry PurgeOffboarded directly
// (no 409 for the illegal self-transition) and succeed, rather than being
// permanently stuck.
func TestOffboardPurgeIsRetriableAfterFailure(t *testing.T) {
	f := registrydb.NewFake()
	store := &flakyPurgeStore{Fake: f, failNext: 1}
	svc := lifecycle.NewService(store)
	ctx := t.Context()

	id := newClientWithIntendedUse(t, f)
	f.TestSetClientStatus(id, "active")

	// First offboard attempt: the flip must commit even though the
	// subsequent purge fails — the purge error surfaces verbatim, never
	// swallowed.
	err := svc.Transition(ctx, id, "offboarded", "operator-1", "", "closing down")
	qt.Assert(t, qt.ErrorIs(err, errPurgeSimulated))

	c, err := f.GetClientFull(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(c.Status, "offboarded")) // flip recorded despite purge failure

	entriesAfterFailedPurge := f.AuditLog()
	qt.Assert(t, qt.Equals(countAuditActions(entriesAfterFailedPurge, "client.transition"), 1))
	qt.Assert(t, qt.Equals(countAuditActions(entriesAfterFailedPurge, "client.purge"), 0)) // never ran

	// Re-submitting the same offboard action on the now-offboarded client:
	// must retry PurgeOffboarded (no 409 for offboarded->offboarded) and
	// succeed — no second flip attempt either.
	err = svc.Transition(ctx, id, "offboarded", "operator-1", "", "closing down")
	qt.Assert(t, qt.IsNil(err))

	entriesAfterRetry := f.AuditLog()
	qt.Assert(t, qt.Equals(countAuditActions(entriesAfterRetry, "client.transition"), 1)) // still just the one flip
	qt.Assert(t, qt.Equals(countAuditActions(entriesAfterRetry, "client.purge"), 1))      // purge actually ran this time
}

// countAuditActions counts entries whose Action equals action.
func countAuditActions(entries []registrydb.AuditLogEntry, action string) int {
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}
