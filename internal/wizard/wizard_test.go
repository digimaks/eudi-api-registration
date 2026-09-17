package wizard

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-eudi/go-eudi-rpcert/ts5"

	"github.com/dativa-lv/eudi-api-registration/internal/registrydb"
)

// fixedClock is the injectable clock every Build test uses — createdAt derives
// from it, so tests never depend on wall time.
func fixedClock() time.Time { return time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC) }

// validLegalPersonForm returns a COMPLETE, valid legal-person FormState
// covering every field: EUID preferred identifier ([ARF TS5 v1.3 §2.4.2.1]),
// multi-lang purpose, an absolute https privacy policy, one mso_mdoc
// credential (explicit claim paths) and one dc+sd-jwt credential (all_claims,
// no claims list — [ARF TS5 v1.3 §2.4.4]), and a supervisoryAuthority with
// country + a contact channel. Tests mutate a deep-enough copy of this rather
// than re-declaring the whole thing.
func validLegalPersonForm() *FormState {
	return &FormState{
		LegalKind:  "legalPerson",
		LegalName:  []string{"Example Retail GmbH"},
		EUID:       "DEUTR.HRB123456",
		Country:    "DE",
		Email:      []string{"contact@rp.example.com"},
		InfoURI:    []string{"https://rp.example.com"},
		SupportURI: []string{"https://rp.example.com/support"},
		TradeName:  "Example Age Check",
		IsPSB:      false,
		SrvDescription: []ts5.MultiLangString{
			{Lang: "en", Content: "Online age verification service"},
			{Lang: "de", Content: "Online-Alterspruefung"},
		},
		Supervisory: ts5.SupervisoryAuthority{
			Name:    "Example State DPA",
			Country: "DE",
			Email:   []string{"dpa@example-ms.eu"},
		},
		IntendedUses: []IntendedUseForm{
			{
				Purpose: []ts5.MultiLangString{{Lang: "en", Content: "Proof of age for online purchase"}},
				PrivacyPolicy: []ts5.Policy{
					{Type: "http://data.europa.eu/eudi/policy/privacy-policy", PolicyURI: "https://rp.example.com/privacy"},
				},
				Credentials: []CredentialForm{
					{
						Format:         FormatMDoc,
						DoctypesOrVCTs: []string{"eu.europa.ec.eudi.pid.1"},
						AllClaims:      false,
						Claims: [][]string{
							{"eu.europa.ec.eudi.pid.1", "age_over_18"},
							{"eu.europa.ec.eudi.pid.1", "nationality"},
						},
					},
					{
						Format:         FormatSDJWT,
						DoctypesOrVCTs: []string{"urn:eudi:pid:1"},
						AllClaims:      true,
					},
				},
			},
		},
	}
}

// --- Golden round-trip ------------------------------------------------------

// TestBuildGoldenLegalPersonRoundTrips is the golden acceptance: a
// complete legal-person form produces a document that (a) round-trips with
// no field loss through ts5.DecodeSignedWRP's own decode path (proving it
// carries no address fields and marshals/unmarshals symmetrically), and (b)
// shares its meaningful top-level key set with the recorded
// wrp-single.json fixture (same KEYS, not values — the fixture predates this
// wizard and was never built by it).
func TestBuildGoldenLegalPersonRoundTrips(t *testing.T) {
	f := validLegalPersonForm()

	doc, ius, err := f.Build(fixedClock)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(doc))
	qt.Assert(t, qt.HasLen(ius, 1))

	raw, err := json.Marshal(doc)
	qt.Assert(t, qt.IsNil(err))

	// (a) ts5.DecodeSignedWRP-compatible round trip: wrap in the registrar
	// API's own signed-payload envelope shape and decode with the SAME
	// public decoder production code uses for registrar responses — proves
	// rejectAddressFields passes (no physicalAddress/postalAddress ever
	// collected) and that no field is lost or retyped by the JSON round trip.
	envelope, err := json.Marshal(map[string]any{
		"iss": "https://registrar.example.test", "iat": 1, "data": json.RawMessage(raw),
	})
	qt.Assert(t, qt.IsNil(err))
	decoded, err := ts5.DecodeSignedWRP(envelope)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(decoded.Data, *doc))

	// (b) shared key-set check against the golden fixture. The fixture is a
	// verbatim vendored copy of go-eudi-rpcert's testdata/ts5/wrp-single.json:
	// eudi-api-registration is a standalone module, so Go resolves testdata/
	// relative to the package dir, which works in every environment.
	fixtureRaw, err := os.ReadFile("testdata/wrp-single.json")
	qt.Assert(t, qt.IsNil(err))
	var fixtureEnv struct {
		Data map[string]any `json:"data"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(fixtureRaw, &fixtureEnv)))

	var built map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &built)))

	// Fields the fixture actually carries that a wizard-built document can
	// also carry (registryURI/isIntermediary are registrar/operator-assigned,
	// never wizard-collected, so they are deliberately excluded from this
	// list — see the fixture's own keys vs. what FormState models).
	for _, key := range []string{
		"tradeName", "supportURI", "srvDescription", "isPSB",
		"isIntermediary", "supervisoryAuthority", "identifier", "country",
	} {
		_, inFixture := fixtureEnv.Data[key]
		_, inBuilt := built[key]
		qt.Check(t, qt.IsTrue(inFixture), qt.Commentf("test bug: %q missing from wrp-single.json fixture", key))
		qt.Check(t, qt.IsTrue(inBuilt), qt.Commentf("%q missing from the wizard-built document", key))
	}
}

// TestBuildGoldenNaturalPersonRoundTrips: the naturalPerson leg of the
// discriminator, otherwise mirroring the legalPerson golden test's round
// trip (no address fields, no field loss).
func TestBuildGoldenNaturalPersonRoundTrips(t *testing.T) {
	f := validLegalPersonForm()
	f.LegalKind = "naturalPerson"
	f.LegalName = nil
	f.GivenName = "Jane"
	f.FamilyName = "Doe"

	doc, _, err := f.Build(fixedClock)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(doc.NaturalPerson))
	qt.Assert(t, qt.IsNil(doc.LegalPerson))
	qt.Check(t, qt.Equals(doc.NaturalPerson.GivenName, "Jane"))
	qt.Check(t, qt.Equals(doc.NaturalPerson.FamilyName, "Doe"))

	raw, err := json.Marshal(doc)
	qt.Assert(t, qt.IsNil(err))
	envelope, err := json.Marshal(map[string]any{"iss": "https://registrar.example.test", "iat": 1, "data": json.RawMessage(raw)})
	qt.Assert(t, qt.IsNil(err))
	decoded, err := ts5.DecodeSignedWRP(envelope)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(decoded.Data, *doc))
}

// TestBuildEUIDIsFirstIdentifier: [ARF TS5 v1.3 §2.4.2.1] — EUID is the PREFERRED
// identifier, so when both an EUID and OtherIDs are present, EUID must sort
// first in the resulting identifier list.
//
// // [ARF TS5 v1.3 §2.4.2.1] EUID preferred
func TestBuildEUIDIsFirstIdentifier(t *testing.T) {
	f := validLegalPersonForm()
	f.OtherIDs = []ts5.Identifier{{Type: "http://data.europa.eu/eudi/id/LEI", Identifier: "529900EXAMPLE0000001"}}

	doc, _, err := f.Build(fixedClock)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(doc.Identifiers, 2))
	qt.Check(t, qt.Equals(doc.Identifiers[0].Type, euidTypeURI))
	qt.Check(t, qt.Equals(doc.Identifiers[0].Identifier, "DEUTR.HRB123456"))
	qt.Check(t, qt.Equals(doc.Identifiers[1].Type, "http://data.europa.eu/eudi/id/LEI"))
}

// TestBuildNoEUIDFallsBackToOtherIDs: the "at least one identifier" rule is
// satisfiable WITHOUT an EUID, via OtherIDs alone.
func TestBuildNoEUIDFallsBackToOtherIDs(t *testing.T) {
	f := validLegalPersonForm()
	f.EUID = ""
	f.OtherIDs = []ts5.Identifier{{Type: "http://data.europa.eu/eudi/id/LEI", Identifier: "529900EXAMPLE0000001"}}

	doc, _, err := f.Build(fixedClock)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(doc.Identifiers, 1))
	qt.Check(t, qt.Equals(doc.Identifiers[0].Identifier, "529900EXAMPLE0000001"))
}

// TestBuildIntendedUseIdentifiersArePendingPlaceholders is the
// projection-adjacent acceptance for the "each ts5.IntendedUse gets a
// wizard-minted IntendedUseIdentifier PLACEHOLDER (pending-<ulid>)" rule:
// every generated id has the "pending-" prefix, and two intended uses never
// collide.
func TestBuildIntendedUseIdentifiersArePendingPlaceholders(t *testing.T) {
	f := validLegalPersonForm()
	f.IntendedUses = append(f.IntendedUses, IntendedUseForm{
		Purpose:       []ts5.MultiLangString{{Lang: "en", Content: "Loyalty programme"}},
		PrivacyPolicy: []ts5.Policy{{Type: "http://data.europa.eu/eudi/policy/privacy-policy", PolicyURI: "https://rp.example.com/privacy-legacy"}},
		Credentials: []CredentialForm{
			{Format: FormatSDJWT, DoctypesOrVCTs: []string{"urn:eudi:pid:1"}, AllClaims: true},
		},
	})

	doc, ius, err := f.Build(fixedClock)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(doc.IntendedUse, 2))
	qt.Assert(t, qt.HasLen(ius, 2))

	seen := map[string]bool{}
	for i, iu := range doc.IntendedUse {
		qt.Check(t, qt.IsTrue(strings.HasPrefix(iu.IntendedUseIdentifier, "pending-")), qt.Commentf("intended use %d", i))
		qt.Check(t, qt.IsFalse(seen[iu.IntendedUseIdentifier]))
		seen[iu.IntendedUseIdentifier] = true
		qt.Check(t, qt.Equals(iu.CreatedAt, "2026-07-09"))
		// The projection's IntendedUseID must match the document's own
		// IntendedUseIdentifier for the same entry (order-preserving).
		qt.Check(t, qt.Equals(ius[i].IntendedUseID, iu.IntendedUseIdentifier))
	}
}

// --- Negative table -----------------------------------------------------

// TestBuildValidationNegativeTable is the negative-table acceptance:
// every listed mutation of an otherwise-valid form must fail Build with the
// named sentinel error, and must NEVER return a non-nil document (a failed
// Build must never hand back a malformed document — invalid input yields an
// error, not a malformed document).
func TestBuildValidationNegativeTable(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(f *FormState)
		wantErr error
	}{
		{
			name:    "neither_legal_kind",
			mutate:  func(f *FormState) { f.LegalKind = "" },
			wantErr: ErrLegalIdentity,
		},
		{
			name:    "unknown_legal_kind",
			mutate:  func(f *FormState) { f.LegalKind = "both" },
			wantErr: ErrLegalIdentity,
		},
		{
			name:    "legal_person_without_legal_name",
			mutate:  func(f *FormState) { f.LegalName = nil },
			wantErr: ErrLegalIdentity,
		},
		{
			name:    "empty_purpose",
			mutate:  func(f *FormState) { f.IntendedUses[0].Purpose = nil },
			wantErr: ErrPurpose,
		},
		{
			name:    "purpose_missing_lang",
			mutate:  func(f *FormState) { f.IntendedUses[0].Purpose = []ts5.MultiLangString{{Content: "no lang"}} },
			wantErr: ErrPurpose,
		},
		{
			name: "non_https_policy_uri",
			mutate: func(f *FormState) {
				f.IntendedUses[0].PrivacyPolicy = []ts5.Policy{{Type: "x", PolicyURI: "http://rp.example.com/privacy"}}
			},
			wantErr: ErrPrivacyPolicy,
		},
		{
			name: "relative_policy_uri",
			mutate: func(f *FormState) {
				f.IntendedUses[0].PrivacyPolicy = []ts5.Policy{{Type: "x", PolicyURI: "/privacy"}}
			},
			wantErr: ErrPrivacyPolicy,
		},
		{
			name:    "no_privacy_policy",
			mutate:  func(f *FormState) { f.IntendedUses[0].PrivacyPolicy = nil },
			wantErr: ErrPrivacyPolicy,
		},
		{
			name:    "no_credentials",
			mutate:  func(f *FormState) { f.IntendedUses[0].Credentials = nil },
			wantErr: ErrCredential,
		},
		{
			name: "unknown_credential_format",
			mutate: func(f *FormState) {
				f.IntendedUses[0].Credentials = []CredentialForm{{Format: "jwt_vc_json", DoctypesOrVCTs: []string{"x"}, AllClaims: true}}
			},
			wantErr: ErrCredentialFormat,
		},
		{
			name: "malformed_claim_path_empty_segment",
			mutate: func(f *FormState) {
				f.IntendedUses[0].Credentials = []CredentialForm{{
					Format: FormatSDJWT, DoctypesOrVCTs: []string{"urn:eudi:pid:1"},
					AllClaims: false, Claims: [][]string{{""}},
				}}
			},
			wantErr: ErrClaimPath,
		},
		{
			name: "malformed_claim_path_empty_path",
			mutate: func(f *FormState) {
				f.IntendedUses[0].Credentials = []CredentialForm{{
					Format: FormatSDJWT, DoctypesOrVCTs: []string{"urn:eudi:pid:1"},
					AllClaims: false, Claims: [][]string{{}},
				}}
			},
			wantErr: ErrClaimPath,
		},
		{
			name: "mdoc_requires_exactly_one_doctype",
			mutate: func(f *FormState) {
				f.IntendedUses[0].Credentials = []CredentialForm{{
					Format: FormatMDoc, DoctypesOrVCTs: []string{"a", "b"}, AllClaims: true,
				}}
			},
			wantErr: ErrCredential,
		},
		{
			name:    "missing_supervisory_authority_country",
			mutate:  func(f *FormState) { f.Supervisory.Country = "" },
			wantErr: ErrSupervisoryAuthority,
		},
		{
			name: "supervisory_authority_no_contact_channel",
			mutate: func(f *FormState) {
				f.Supervisory.Email = nil
				f.Supervisory.Phone = nil
				f.Supervisory.FormURI = nil
			},
			wantErr: ErrSupervisoryAuthority,
		},
		{
			name:    "invalid_country",
			mutate:  func(f *FormState) { f.Country = "Germany" },
			wantErr: ErrCountry,
		},
		{
			name:    "no_intended_uses",
			mutate:  func(f *FormState) { f.IntendedUses = nil },
			wantErr: ErrIntendedUse,
		},
		{
			name: "no_identifier_at_all",
			mutate: func(f *FormState) {
				f.EUID = ""
				f.OtherIDs = nil
			},
			wantErr: ErrIdentifier,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validLegalPersonForm()
			tt.mutate(f)

			doc, ius, err := f.Build(fixedClock)
			qt.Assert(t, qt.ErrorIs(err, tt.wantErr))
			qt.Check(t, qt.IsNil(doc))
			qt.Check(t, qt.IsNil(ius))
		})
	}
}

// --- Projection ----------------------------------------------------------

// TestBuildProjectionMdocTwoClaimPaths is the projection acceptance:
// an mso_mdoc credential with 2 claim paths converts to
// RegisteredCredentialJSON EXACTLY (all_claims:false, paths in dcql JSON
// form — [][]any of string segments, matching go-dcql's toClaimPaths input
// shape).
func TestBuildProjectionMdocTwoClaimPaths(t *testing.T) {
	f := validLegalPersonForm()
	f.IntendedUses[0].Credentials = []CredentialForm{
		{
			Format:         FormatMDoc,
			DoctypesOrVCTs: []string{"eu.europa.ec.eudi.pid.1"},
			AllClaims:      false,
			Claims: [][]string{
				{"eu.europa.ec.eudi.pid.1", "age_over_18"},
				{"eu.europa.ec.eudi.pid.1", "nationality"},
			},
		},
	}

	_, ius, err := f.Build(fixedClock)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(ius, 1))
	qt.Assert(t, qt.HasLen(ius[0].Credentials, 1))

	got := ius[0].Credentials[0]
	want := registrydb.RegisteredCredentialJSON{
		Format:         "mso_mdoc",
		DoctypesOrVCTs: []string{"eu.europa.ec.eudi.pid.1"},
		AllClaims:      false,
		Claims: [][]any{
			{"eu.europa.ec.eudi.pid.1", "age_over_18"},
			{"eu.europa.ec.eudi.pid.1", "nationality"},
		},
	}
	qt.Assert(t, qt.DeepEquals(got, want))

	// Exact wire shape, not just a Go-level DeepEquals: the marshaled JSON
	// must carry "all_claims":false and the claim paths as JSON arrays.
	gotJSON, err := json.Marshal(got)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(gotJSON),
		`{"format":"mso_mdoc","doctypes_or_vcts":["eu.europa.ec.eudi.pid.1"],"all_claims":false,"claims":[["eu.europa.ec.eudi.pid.1","age_over_18"],["eu.europa.ec.eudi.pid.1","nationality"]]}`))
}

// TestBuildProjectionAllClaimsWhenNoClaimsList is the projection acceptance's
// other half: a credential the wizard collected with NO claims list
// (AllClaims:true) converts to RegisteredCredentialJSON with all_claims:true
// and an ABSENT (not empty) claims key: in a TS5 registration the attestation is
// then described by its schema or rulebook ([ARF TS5 v1.3 §2.4.4]), NOT by an
// enumerated claim list.
func TestBuildProjectionAllClaimsWhenNoClaimsList(t *testing.T) {
	f := validLegalPersonForm()
	f.IntendedUses[0].Credentials = []CredentialForm{
		{Format: FormatSDJWT, DoctypesOrVCTs: []string{"urn:eudi:pid:1"}, AllClaims: true},
	}

	_, ius, err := f.Build(fixedClock)
	qt.Assert(t, qt.IsNil(err))
	got := ius[0].Credentials[0]
	qt.Check(t, qt.IsTrue(got.AllClaims))
	qt.Check(t, qt.HasLen(got.Claims, 0))

	gotJSON, err := json.Marshal(got)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(gotJSON),
		`{"format":"dc+sd-jwt","doctypes_or_vcts":["urn:eudi:pid:1"],"all_claims":true}`))
}

// TestBuildMdocMeta / TestBuildSDJWTMeta pin the per-format meta shape
// go-eudi-rpcert's own wrprc.go metaJSON expects (doctype_value singular for
// mso_mdoc, vct_values plural for dc+sd-jwt — OID4VP Appendix B.2.3/B.3.5).
func TestBuildMdocMeta(t *testing.T) {
	f := validLegalPersonForm()
	f.IntendedUses[0].Credentials = []CredentialForm{
		{Format: FormatMDoc, DoctypesOrVCTs: []string{"eu.europa.ec.eudi.pid.1"}, AllClaims: true},
	}
	doc, _, err := f.Build(fixedClock)
	qt.Assert(t, qt.IsNil(err))
	var meta struct {
		DoctypeValue string `json:"doctype_value"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(doc.IntendedUse[0].Credentials[0].Meta, &meta)))
	qt.Check(t, qt.Equals(meta.DoctypeValue, "eu.europa.ec.eudi.pid.1"))
}

func TestBuildSDJWTMeta(t *testing.T) {
	f := validLegalPersonForm()
	f.IntendedUses[0].Credentials = []CredentialForm{
		{Format: FormatSDJWT, DoctypesOrVCTs: []string{"urn:eudi:pid:1", "urn:eudi:pid:2"}, AllClaims: true},
	}
	doc, _, err := f.Build(fixedClock)
	qt.Assert(t, qt.IsNil(err))
	var meta struct {
		VCTValues []string `json:"vct_values"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(doc.IntendedUse[0].Credentials[0].Meta, &meta)))
	qt.Check(t, qt.DeepEquals(meta.VCTValues, []string{"urn:eudi:pid:1", "urn:eudi:pid:2"}))
}

// TestBuildNilFormStateClockDefaultsToTimeNow: a nil clock must not panic
// and must default sensibly (Build's signature takes `now func() time.Time`
// — a nil func value would panic on call if Build ever invoked it directly
// without this guard).
func TestBuildNilClockDoesNotPanic(t *testing.T) {
	f := validLegalPersonForm()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Build panicked with a nil clock: %v", r)
		}
	}()
	_, _, err := f.Build(nil)
	qt.Assert(t, qt.IsNil(err))
}
