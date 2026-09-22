// Package lifecycle wraps registrydb.Store.TransitionClient with per-edge
// side effects and service-level activation preconditions. The state
// machine's legal/illegal edges are enforced ENTIRELY by registrydb.Store
// (registry.transition_client's matrix, mirrored in registrydb.Fake for
// tests) — this package never re-implements that matrix and never overrides
// its verdict (call the store and surface its error; do NOT re-implement the
// matrix in Go). It only adds two things layered on top:
//
//   - a precondition checked BEFORE attempting a "-> active" transition, but
//     ONLY when the current status is one of the edge's two LEGAL
//     predecessors (registered, suspended): a recorded registrar identity
//     (the registrar's URL, absolute https, and the identifier it assigned),
//     at least one non-revoked intended use, plus a TS5OK seam for the
//     "ARF TS5 last check ok" half —
//     the ARF TS5 verification job has not landed yet, so TS5OK defaults to
//     permissive until that check is wired. Gating the precondition on the
//     predecessor matters because otherwise it would run for EVERY current
//     status, including illegal predecessors (e.g. draft), and mask the
//     store's own err:registry:illegal_transition (409) behind a service-level
//     err:client:intendedUseRequired (422) for a client with zero intended
//     uses — the wrong error for that input class. Knowing the two legal
//     predecessors of "active" is inherent to the precondition being about
//     that specific edge; it is not the whole matrix;
//   - a side effect that keeps "-> offboarded" idempotent+retriable:
//     Store.PurgeOffboarded (keys revoked + evidence purged per retention;
//     session blocking happens automatically via the session service's own
//     client-status gate, no code here) runs after a successful flip into
//     "offboarded". If purge fails after the flip commits, the client is
//     stuck offboarded with an unpurged tail — and "offboarded -> offboarded"
//     is an illegal edge, so a naive retry would hit the store's 409 instead
//     of retrying the purge. This package special-cases that one case: when
//     the client is ALREADY offboarded, it skips the (illegal)
//     self-transition and just re-runs the idempotent PurgeOffboarded,
//     surfacing its error (never swallowed) so an operator can tell the retry
//     itself failed.
//
// Every edge still goes through Store.TransitionClient except that one
// already-offboarded retry case, so every OTHER edge surfaces exactly the
// store's own err:registry:illegal_transition (409) — this package adds
// checks, it never loosens or overrides the store's own verdict.
// ARF Topic 52 (client lifecycle state machine).
package lifecycle

import (
	"context"
	"fmt"
	"net/url"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/digimaks/eudi-api-registration/internal/registrydb"
)

// stateActive / stateOffboarded name the two states this package attaches
// extra behavior to. They are used only to decide WHEN to run that extra
// behavior — never to decide an edge's legality (see the package doc
// comment above): this package has no opinion on which states may legally
// reach "active" or "offboarded", only on what to do once the store itself
// has (or is about to) put a client there.
//
// stateRegistered / stateSuspended are the state machine's two LEGAL
// predecessors of "active" (registry.transition_client's v_legal list —
// mirrored in registrydb.Fake's legalTransitions). The "-> active"
// intended-use precondition below is scoped to exactly these two: this is
// knowledge of one edge's legal predecessors, not the full matrix — see the
// package doc comment.
const (
	stateActive     = "active"
	stateOffboarded = "offboarded"
	stateRegistered = "registered"
	stateSuspended  = "suspended"
)

// Service wraps a registrydb.Store with the lifecycle side effects and
// activation precondition described above. Construct with NewService (it
// installs the permissive default TS5OK); a zero-value Service is usable
// only if the caller sets both fields itself.
type Service struct {
	Store registrydb.Store

	// TS5OK is the seam for the "-> active" precondition's "ARF TS5 last
	// check ok" half. The ARF TS5 verification job has not landed yet, so
	// this is deliberately NOT implemented here — NewService installs a
	// permissive default (always true). The real ARF TS5 check will be wired
	// in here.
	TS5OK func(ctx context.Context, clientID string) bool
}

// NewService returns a Service wrapping store, with the permissive default
// TS5OK hook installed.
func NewService(store registrydb.Store) *Service {
	return &Service{
		Store: store,
		TS5OK: func(context.Context, string) bool { return true },
	}
}

// Transition drives one client-lifecycle edge of the state machine.
//
// For "-> active" and "-> offboarded" targets it first reads the client's
// CURRENT status (GetClientFull — also the existence check: an unknown
// clientID surfaces the store's own err:registry:not_found here, before
// either special case below runs) and branches:
//
//   - "-> active" with current status registered or suspended (the edge's
//     two LEGAL predecessors): the intended-use/ARF TS5 precondition runs
//     BEFORE the client is touched. Any OTHER current status (e.g. draft)
//     skips the precondition entirely and falls through to
//     Store.TransitionClient, whose own err:registry:illegal_transition (409)
//     is the correct error for that input class (see the package doc comment).
//   - "-> offboarded" with current status ALREADY offboarded: the
//     self-transition is illegal, so this returns early and just re-runs
//     the idempotent Store.PurgeOffboarded instead — an operator retrying
//     offboard after a previous purge failure gets a retry, not a 409
//     (see the package doc comment). The purge error, if any, surfaces
//     verbatim (never swallowed).
//
// Every other edge (including a first, non-retry "-> offboarded") calls
// Store.TransitionClient — the sole authority on the edge's legality; its
// error, if any, surfaces verbatim — then, for "-> offboarded", runs the
// purge side effect after a successful flip.
//
// actor is the caller's account id, supplied by the route handler (the
// routes pass "api"), never a blank string — Store.TransitionClient and
// PurgeOffboarded both audit against it.
func (s *Service) Transition(ctx context.Context, clientID, toState, actor, evidenceRef, reason string) error {
	if toState == stateActive || toState == stateOffboarded {
		current, err := s.Store.GetClientFull(ctx, clientID)
		if err != nil {
			return err
		}

		if toState == stateActive && (current.Status == stateRegistered || current.Status == stateSuspended) {
			if err := s.checkActivationPreconditions(ctx, current); err != nil {
				return err
			}
		}

		if toState == stateOffboarded && current.Status == stateOffboarded {
			return s.Store.PurgeOffboarded(ctx, clientID, actor)
		}
	}

	if err := s.Store.TransitionClient(ctx, clientID, toState, actor, evidenceRef, reason); err != nil {
		return err
	}

	if toState == stateOffboarded {
		if err := s.Store.PurgeOffboarded(ctx, clientID, actor); err != nil {
			return err
		}
	}

	return nil
}

// checkActivationPreconditions enforces the "-> active" gate: a recorded
// registrar identity, at least one non-revoked intended use, and (once wired)
// a passing ARF TS5 check. c is the client's current row, already read by
// Transition (which thereby also established its existence).
func (s *Service) checkActivationPreconditions(ctx context.Context, c *registrydb.ClientFull) error {
	// The registrar identity travels in every presentation request the
	// client's sessions make; a client activated without it fails at its first
	// session, with nothing in the onboarding flow having said so. Caught here,
	// while the operator is still onboarding, and named with the call that
	// records it — a dedicated call outside the registration document and the
	// lifecycle transitions, which is exactly why it is the step that gets
	// missed. Checked first: it needs no further read.
	if c.ClientIdentifier == "" || !isAbsoluteHTTPSURL(c.RegistryURI) {
		return pkerrors.NewProblem("err:client:registrarIdentityRequired",
			pkerrors.WithPublicDetail("the client has no registrar identity recorded; set it with PUT /api/clients/{id}/registrar-identity (registryUri as an absolute https URL, plus clientIdentifier) before activating"))
	}

	ius, err := s.Store.ListIntendedUses(ctx, c.ID)
	if err != nil {
		return err
	}
	if !anyNonRevoked(ius) {
		return pkerrors.NewProblem("err:client:intendedUseRequired",
			pkerrors.WithDetail(fmt.Sprintf("client %s has no non-revoked intended use", c.ID)))
	}

	if !s.ts5OK()(ctx, c.ID) {
		return pkerrors.NewProblem("err:client:ts5CheckFailed")
	}

	return nil
}

// isAbsoluteHTTPSURL mirrors the check the registrar-identity endpoint applies
// when the value is written: url.Parse alone accepts relative references and
// other schemes without error, so scheme and host are checked explicitly. A
// local restatement rather than a shared helper — the two live in different
// packages, and a check that silently drifts is worse than one restated where
// it is enforced.
func isAbsoluteHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// ts5OK returns s.TS5OK, or the permissive default if the caller built a
// zero-value Service directly rather than going through NewService.
func (s *Service) ts5OK() func(ctx context.Context, clientID string) bool {
	if s.TS5OK != nil {
		return s.TS5OK
	}
	return func(context.Context, string) bool { return true }
}

// anyNonRevoked reports whether ius contains at least one intended use whose
// RevokedAt is unset.
func anyNonRevoked(ius []registrydb.IntendedUse) bool {
	for _, iu := range ius {
		if iu.RevokedAt == "" {
			return true
		}
	}
	return false
}
