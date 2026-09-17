package eudiapiregistration

import (
	"testing"

	"github.com/go-quicktest/qt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/gmb-lib/go-platform-kit/observability"
)

// redactedLogger boots this module's TestApp, swaps its logger for
// an observer sink, and re-applies observability.EnableRedaction against
// that sink core — the same seam the other services' redaction tests use, so
// the assertion below sees exactly what a production sink would receive.
func redactedLogger(t *testing.T, policy *observability.RedactionPolicy) (*zap.Logger, *observer.ObservedLogs) {
	t.Helper()

	app := NewTestApp(t)

	core, logs := observer.New(zapcore.DebugLevel)
	qt.Assert(t, qt.IsNil(app.ReplaceLogger(zap.New(core))))
	observability.EnableRedaction(app.App, policy)

	return app.Log(), logs
}

// TestClaimValueNeverReachesSink is the ARF AS-RP-01-002 canary (no attribute
// values in logs): every field this service's ARF TS7 deletion flow might one
// day log by mistake must never survive to the sink. Covers the security-sweep
// drop set ("subject"/"claim") plus the credential-PII set shared with the
// other services.
func TestClaimValueNeverReachesSink(t *testing.T) {
	lg, logs := redactedLogger(t, RedactionPolicy())

	const canary = "CANARY-CLAIM-VALUE-77f1"
	lg.Info("deletion identification result",
		zap.String("subject", canary),          // DROPPED (DeletionRequestEvent.subject — verified claim VALUES)
		zap.String("claims", canary),           // DROPPED ("claim" substring)
		zap.String("credentials", canary),      // DROPPED
		zap.String("result", canary),           // DROPPED
		zap.String("result_jwe", canary),       // DROPPED
		zap.String("vp_token", canary),         // DROPPED
		zap.String("disclosure_salt", canary),  // DROPPED (salts)
		zap.String("kb_jwt_payload", canary),   // DROPPED
		zap.String("device_signature", canary), // DROPPED
		zap.String("portrait", canary),         // DROPPED
		zap.String("biometric_template", canary),
		zap.String("document_number", canary),
		zap.String("documentNumber", canary), // camelCase, no separator normalization
		// attribute_names is deliberately loggable (names only, never
		// values — ARF AS-RP-48-004); asserted separately below.
		zap.String("attribute_names", "given_name,family_name"),
		zap.String("check", "device_binding"), // kept — outcome identifiers are fine
		// Deliberately NOT "session_id": the fleet default already drops any
		// key containing "session". Use correlation_id instead.
		zap.String("correlation_id", "01JZX0S"),
	)

	qt.Assert(t, qt.Equals(logs.Len(), 1))
	entry := logs.All()[0]
	for _, f := range entry.Context {
		qt.Assert(t, qt.Not(qt.Equals(f.String, canary)),
			qt.Commentf("field %q leaked the claim value", f.Key))
	}

	found := map[string]string{}
	for _, f := range entry.Context {
		found[f.Key] = f.String
	}
	qt.Assert(t, qt.Equals(found["check"], "device_binding"))
	qt.Assert(t, qt.Equals(found["correlation_id"], "01JZX0S"))
	qt.Assert(t, qt.Equals(found["attribute_names"], "given_name,family_name"))
}

// TestSessionIDFieldIsDroppedByFleetDefault documents the same fleet-default
// gotcha the other services' redaction tests document: a literal "session_id"
// field is dropped by the kit's own DropKeys (substring "session"), not by
// this service's extension.
func TestSessionIDFieldIsDroppedByFleetDefault(t *testing.T) {
	lg, logs := redactedLogger(t, RedactionPolicy())

	lg.Info("session lookup", zap.String("session_id", "01JZX0S"))

	qt.Assert(t, qt.Equals(logs.Len(), 1))
	for _, f := range logs.All()[0].Context {
		qt.Assert(t, qt.Not(qt.Equals(f.Key, "session_id")),
			qt.Commentf("session_id is expected to be dropped by the fleet default policy"))
	}
}

// TestFleetDefaultsRetained: the fleet defaults must survive extension (add,
// never weaken) — RedactionPolicy() is a strict superset.
func TestFleetDefaultsRetained(t *testing.T) {
	p := RedactionPolicy()
	def := observability.DefaultRedactionPolicy()
	for _, k := range def.DropKeys {
		qt.Check(t, qt.SliceContains(p.DropKeys, k), qt.Commentf("missing fleet default drop key %q", k))
	}
	for _, k := range def.MaskKeys {
		qt.Check(t, qt.SliceContains(p.MaskKeys, k), qt.Commentf("missing fleet default mask key %q", k))
	}
}

// TestRedactionPolicyHasExpectedDropKeys pins the literal drop set
// (including this service's own "subject" addition) so a future refactor that
// accidentally drops one of these entries fails a test, not just a canary log
// line — this IS the security-sweep evidence for "the redaction drop-set
// covers subject/claims".
func TestRedactionPolicyHasExpectedDropKeys(t *testing.T) {
	p := RedactionPolicy()
	for _, k := range []string{
		"claim", "disclosure", "salt", "vp_token", "kb_jwt", "device_signature",
		"deviceauth", "portrait", "biometric", "document_number", "documentnumber",
		"credentials", "result", "result_jwe", "subject",
	} {
		qt.Check(t, qt.SliceContains(p.DropKeys, k), qt.Commentf("expected drop key %q missing", k))
	}
}
