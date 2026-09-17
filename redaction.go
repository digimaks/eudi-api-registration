package eudiapiregistration

import "github.com/gmb-lib/go-platform-kit/observability"

// RedactionPolicy extends the fleet default for eudi-api-registration, which can
// briefly hold verified attribute VALUES in memory during an ARF TS7 deletion
// flow (wallet-authenticated deletion request) and handles legal-entity
// evidence during onboarding. ARF AS-RP-01-002 / GDPR: claim values never
// reach logs, traces, or error messages. Mirrors eudi-api-management's
// credential-PII drop set (same attribute fields, redacted the same way); keep
// the two in lockstep. The drop set adds no NEW attribute-value fields of its
// own, but it must be in place before anything logs a struct that might carry
// one. Additive-only over observability.DefaultRedactionPolicy (add, never
// weaken). Extend this list BEFORE logging any new struct.
//
// Matching is case-insensitive SUBSTRING on top-level field keys, with NO
// separator normalization — so "claim" catches "claims"/"claim_value" but a
// camelCase "documentNumber" needs its own "documentnumber" entry. Matching is
// top-level-key only: NEVER log a nested map/struct of claims via
// zap.Any/zap.Reflect — the redacting core cannot see inside it, so sensitive
// keys within would bypass this policy entirely. Log individual scalar fields
// instead.
//
// ARF AS-RP-48-004 note: the ARF TS7 deletion-request log stores attribute
// NAMES only (which claims were disclosed), never values — so
// "attribute_names" is deliberately NOT in the drop set below: it is the one
// field this service is REQUIRED to log, and it never carries a value, only a
// claim identifier string (e.g. "given_name"). Do not add it to
// DropKeys/MaskKeys.
//
// Gotcha (shared with the other services): the fleet default already drops the
// substring "session", so a literal "session_id" log field is silently
// dropped. Identify a session in logs via "correlation_id" instead (bound
// automatically by go-platform-kit/correlation's middleware).
func RedactionPolicy() *observability.RedactionPolicy {
	p := observability.DefaultRedactionPolicy()
	p.DropKeys = append(p.DropKeys,
		// credential attribute values — same set as eudi-api-management/eudi-verifier-core
		"claim",            // disclosed claim values (claims, claim_value, claim_values)
		"disclosure",       // disclosure content + salts (disclosure_salt, disclosures)
		"salt",             // disclosure salts logged standalone
		"vp_token",         // raw vp_token content
		"kb_jwt",           // KB-JWT payloads (kb_jwt_payload, kb_jwt)
		"device_signature", // mdoc device signatures
		"deviceauth",       // mdoc DeviceAuth structures
		"portrait",         // portrait images (PII bytes)
		"biometric",        // biometric templates
		"document_number",  // document numbers
		"documentnumber",   // camelCase documentNumber (no separator normalization)
		// this service's ARF TS7 deletion result envelope (eudi-verifier-core
		// session forwarding) — same keys eudi-api-management's handoff path drops
		"credentials", // result.credentials[] — claim-bearing
		"result",      // decrypted verification-session result plaintext
		"result_jwe",  // encrypted handoff payload
		// `subject` is the ONE field this service's ARF TS7 deletion flow ever
		// builds that carries verified claim VALUES on the wire (forwarded once
		// to the client's webhook, then zeroed). Never log an event/response
		// struct containing it via zap.Any/zap.Reflect (see this policy's own
		// doc comment above) — but drop the key too, belt and suspenders,
		// exactly like "credentials"/"result" above.
		"subject",
	)
	return p
}
