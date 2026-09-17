// Package routes (this file): PUT /api/clients/{id}/registration tests —
// TestAPISetRegistrationBuildsDoc (a complete,
// wizard.FormState.Build-valid body persists a WRP document + one
// intended-use projection and the response reports the client's current
// state), TestAPISetRegistrationInvalidIs422 (a Build validation failure
// surfaces as err:api:registrationInvalid, 422),
// TestAPISetRegistrationMalformedJSONIs400 (a body that is not valid JSON
// at all surfaces as err:api:invalidBody, 400), plus FuzzParseRegistration,
// the fuzz target for this untrusted-input parser: decoding
// apiRegistrationRequest and running toFormState().Build on whatever comes
// out must never panic on arbitrary decodable input.
package routes

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// validRegistrationBody is a complete apiRegistrationRequest JSON body that
// satisfies wizard.FormState.Build's real requirements end to end (pinned
// down against internal/wizard/wizard_test.go's validLegalPersonForm and
// wizard.go's own sentinel-error preconditions): legalPerson + legalName,
// an otherIds identifier (exercising the otherIds -> []ts5.Identifier
// mapping; deliberately NO euid, proving "at least one identifier" is
// satisfiable via otherIds alone — same case wizard_test.go's
// TestBuildNoEUIDFallsBackToOtherIDs pins on the wizard side), a 2-letter
// country, one intended use with a lang+text purpose, an absolute https
// privacy policy, one mso_mdoc credential with exactly one doctype value
// (FormatMDoc requires exactly one) and one non-empty claim path, and a
// supervisory authority with country + an email contact channel.
const validRegistrationBody = `{
  "legalKind":"legalPerson",
  "legalName":["Acme Demo RP Ltd"],
  "country":"LV",
  "supportUri":["https://acme.test/support"],
  "otherIds":[{"type":"http://data.europa.eu/eudi/id/LEI","identifier":"529900EXAMPLE0000001"}],
  "intendedUses":[{
    "purpose":[{"lang":"en","text":"Age-over-18 verification"}],
    "privacyPolicy":[{"uri":"https://acme.test/privacy"}],
    "credentials":[{"format":"mso_mdoc","doctypesOrVcts":["eu.europa.ec.eudi.pid.1"],"claims":[["age_over_18"]]}]
  }],
  "supervisoryAuthority":{"name":"Data State Inspectorate","country":"LV","email":["dpa@example-ms.eu"]}
}`

// TestAPISetRegistrationBuildsDoc core acceptance: a structured, valid body
// maps to wizard.FormState, builds a ts5.WalletRelyingParty document via the
// SAME Build the client-facing wizard uses, persists it (+ its one
// intended-use projection) via SaveWRPDocument, and the 200 response reports
// {id, state, intendedUses} (the RegistrationResult shape) — state is read
// back from GetClientFull, not hardcoded, and this endpoint never itself
// transitions the client (still "draft", matching CreateDraftClient's own
// default).
func TestAPISetRegistrationBuildsDoc(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme Demo RP", "", "api")
	qt.Assert(t, qt.IsNil(err))

	resp, err := tc.Put("/api/clients/"+id+"/registration", []byte(validRegistrationBody), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	var result apiRegistrationResult
	qt.Assert(t, qt.IsNil(json.Unmarshal(readBody(t, resp), &result)))
	qt.Check(t, qt.Equals(result.ID, id))
	qt.Check(t, qt.Equals(result.State, "draft"))
	qt.Check(t, qt.Equals(result.IntendedUses, 1))

	// The WRP document + intended-use projection were actually PERSISTED,
	// not just echoed back in the response.
	full, err := fake.GetClientFull(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(len(full.WRPDocument) > 0 && string(full.WRPDocument) != "null"))
	ius, err := fake.ListIntendedUses(t.Context(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(ius), 1))
}

// TestAPISetRegistrationInvalidIs422 is otherwise-valid all the way through
// the identifier/country/supervisory-authority checks — the ONLY defect is
// an empty intendedUses array — so this specifically pins
// wizard.ErrIntendedUse's 422 mapping (err:api:registrationInvalid), not
// some earlier, unrelated Build failure.
func TestAPISetRegistrationInvalidIs422(t *testing.T) {
	tApp, _, fake := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")
	id, err := fake.CreateDraftClient(t.Context(), "Acme", "", "api")
	qt.Assert(t, qt.IsNil(err))

	body := `{"legalKind":"legalPerson","legalName":["X"],"country":"LV","euid":"LVTEST123",
	  "supervisoryAuthority":{"country":"LV","email":["dpa@example.test"]},"intendedUses":[]}`
	resp, err := tc.Put("/api/clients/"+id+"/registration", []byte(body), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
}

// TestAPISetRegistrationMalformedJSONIs400 exercises the err:api:invalidBody
// path for a body that isn't valid JSON at all — decode fails before
// toFormState/Build (and before any Store call) ever runs, so an unknown
// client id would not change this outcome; a literal path placeholder is
// enough.
func TestAPISetRegistrationMalformedJSONIs400(t *testing.T) {
	tApp, _, _ := testAppWithAPI(t, "k3y")
	tApp.Start(t)
	defer tApp.Stop()
	tc := tApp.TestClient()
	key := tc.WithHeader("X-API-Key", "k3y")

	resp, err := tc.Put("/api/clients/x/registration", []byte(`not json`), key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

// FuzzParseRegistration is the fuzz target for this endpoint's
// untrusted-input parser: decoding must never panic, and — for every input
// that DOES decode — toFormState().Build must never panic either, no
// matter how the decoded fields are populated (empty slices, wildly long
// strings, unicode, malformed claim-path shapes, ...). The fixed clock
// keeps Build deterministic; this target checks absence-of-panic only, not
// any particular Build outcome.
func FuzzParseRegistration(f *testing.F) {
	f.Add([]byte(validRegistrationBody))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var req apiRegistrationRequest
		if json.Unmarshal(data, &req) != nil {
			return
		}
		fs := req.toFormState()
		_, _, _ = fs.Build(func() time.Time { return time.Unix(0, 0) })
	})
}
