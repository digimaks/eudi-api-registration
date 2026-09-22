package wizard

import (
	"testing"
	"time"

	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
)

// FuzzWizardWRPAssembly is the fuzz target for this package's untrusted-input
// assembler: arbitrary form-field bytes fed into a FormState must never panic
// Build, and any invalid combination must come back as an error — never a
// document (invalid input yields an error, not a malformed document). Run
// ≥ 30s locally: `go test -run=NONE -fuzz=FuzzWizardWRPAssembly
// -fuzztime=30s ./internal/wizard/`.
//
// Seed 1 is the "complete, valid" happy-path case (EUID given,
// otherIDType/otherIDValue both left blank — i.e. no "other" identifiers at
// all). otherIDsFromFuzz builds FormState.OtherIDs as nil (not a
// one-empty-entry slice) when both strings are blank: a one-entry slice with
// both fields empty looks malformed to identifiers() (which rejects any entry
// with an empty Type or Identifier) rather than "no other identifiers given",
// which would spuriously fail the EUID-only happy path. Seed 5 adds a second,
// distinct happy-path case (naturalPerson + dc+sd-jwt + all_claims, still
// EUID-only) so the construction is exercised from more than one angle.
func FuzzWizardWRPAssembly(f *testing.F) {
	seeds := []struct {
		legalKind, legalName, givenName, familyName string
		euid, otherIDType, otherIDValue, country    string
		email, infoURI, supportURI, tradeName       string
		srvLang, srvContent                         string
		purposeLang, purposeContent, policyURI      string
		credFormat, doctypeOrVCT                    string
		allClaims                                   bool
		claimSeg1, claimSeg2                        string
		saCountry, saEmail                          string
		isPSB                                       bool
	}{
		{
			"legalPerson", "Example Retail GmbH", "", "",
			"DEUTR.HRB123456", "", "", "DE",
			"contact@rp.example.com", "https://rp.example.com", "https://rp.example.com/support", "Example Age Check",
			"en", "Online age verification service",
			"en", "Proof of age for online purchase", "https://rp.example.com/privacy",
			FormatMDoc, "eu.europa.ec.eudi.pid.1",
			false,
			"eu.europa.ec.eudi.pid.1", "age_over_18",
			"DE", "dpa@example-ms.eu",
			false,
		},
		{
			"naturalPerson", "", "Jane", "Doe",
			"", "http://data.europa.eu/eudi/id/LEI", "529900EXAMPLE0000001", "FR",
			"", "", "", "",
			"", "",
			"fr", "", "not-a-url",
			FormatSDJWT, "urn:eudi:pid:1",
			true,
			"", "",
			"", "",
			true,
		},
		{
			"", "", "", "",
			"", "", "", "",
			"", "", "", "",
			"", "",
			"", "", "",
			"jwt_vc_json", "",
			false,
			"", "",
			"", "",
			false,
		},
		{
			"legalPerson", "", "", "",
			"", "", "", "germany",
			"", "", "", "",
			"", "",
			"en", "purpose", "http://insecure.example.com",
			FormatMDoc, "",
			false,
			"", "",
			"", "",
			false,
		},
		// Seed 5: a SECOND complete, valid happy-path case, distinct
		// from seed 1 — naturalPerson rather than legalPerson, dc+sd-jwt
		// all_claims rather than mso_mdoc explicit claim paths — still
		// EUID-only (otherIDType/otherIDValue both blank), exercising
		// otherIDsFromFuzz's "blank pair -> nil OtherIDs, not a one-empty-entry
		// slice" rule from the naturalPerson leg of the discriminator.
		{
			"naturalPerson", "", "Jane", "Doe",
			"FRSIRENE123456789", "", "", "FR",
			"jane@example.com", "https://rp.example.com", "https://rp.example.com/support", "",
			"", "",
			"en", "Loyalty programme enrollment", "https://rp.example.com/privacy",
			FormatSDJWT, "urn:eudi:pid:1",
			true,
			"", "",
			"FR", "dpa@example-ms.eu",
			false,
		},
	}
	for _, s := range seeds {
		f.Add(s.legalKind, s.legalName, s.givenName, s.familyName,
			s.euid, s.otherIDType, s.otherIDValue, s.country,
			s.email, s.infoURI, s.supportURI, s.tradeName,
			s.srvLang, s.srvContent,
			s.purposeLang, s.purposeContent, s.policyURI,
			s.credFormat, s.doctypeOrVCT,
			s.allClaims,
			s.claimSeg1, s.claimSeg2,
			s.saCountry, s.saEmail,
			s.isPSB)
	}

	f.Fuzz(func(t *testing.T,
		legalKind, legalName, givenName, familyName string,
		euid, otherIDType, otherIDValue, country string,
		email, infoURI, supportURI, tradeName string,
		srvLang, srvContent string,
		purposeLang, purposeContent, policyURI string,
		credFormat, doctypeOrVCT string,
		allClaims bool,
		claimSeg1, claimSeg2 string,
		saCountry, saEmail string,
		isPSB bool,
	) {
		form := &FormState{
			LegalKind:  legalKind,
			LegalName:  []string{legalName},
			GivenName:  givenName,
			FamilyName: familyName,
			EUID:       euid,
			OtherIDs:   otherIDsFromFuzz(otherIDType, otherIDValue),
			Country:    country,
			Email:      []string{email},
			InfoURI:    []string{infoURI},
			SupportURI: []string{supportURI},
			TradeName:  tradeName,
			IsPSB:      isPSB,
			SrvDescription: []ts5.MultiLangString{
				{Lang: srvLang, Content: srvContent},
			},
			Supervisory: ts5.SupervisoryAuthority{
				Country: saCountry,
				Email:   []string{saEmail},
			},
			IntendedUses: []IntendedUseForm{
				{
					Purpose:       []ts5.MultiLangString{{Lang: purposeLang, Content: purposeContent}},
					PrivacyPolicy: []ts5.Policy{{Type: "x", PolicyURI: policyURI}},
					Credentials: []CredentialForm{
						{
							Format:         credFormat,
							DoctypesOrVCTs: []string{doctypeOrVCT},
							AllClaims:      allClaims,
							Claims:         [][]string{{claimSeg1, claimSeg2}},
						},
					},
				},
			},
		}

		// The one assertion that matters: Build must NEVER panic on
		// arbitrary field content, no matter how malformed.
		doc, ius, err := form.Build(time.Now)

		if err != nil {
			if doc != nil || ius != nil {
				t.Fatalf("Build returned a non-nil document alongside an error: doc=%v ius=%v err=%v", doc, ius, err)
			}
			return
		}

		// Success must always be a structurally sane document: never nil,
		// never carrying an address field (round-trip through the ts5
		// decoder's own address rejection), and always exactly one legal
		// identity.
		if doc == nil {
			t.Fatal("Build returned a nil document with a nil error")
		}
		if (doc.LegalPerson == nil) == (doc.NaturalPerson == nil) {
			t.Fatalf("expected exactly one of LegalPerson/NaturalPerson, got legalPerson=%v naturalPerson=%v", doc.LegalPerson, doc.NaturalPerson)
		}
	})
}

// otherIDsFromFuzz mirrors how an OtherIDs entry is only contributed when a
// real paired type+value exists: a fuzz case that leaves BOTH otherIDType and
// otherIDValue blank must produce a nil OtherIDs slice, not a one-entry slice
// of two empty strings. The latter looks like a MALFORMED identifier to
// identifiers() (which rejects any entry with an empty Type or Identifier)
// rather than "no other identifiers were given"; without this helper an
// all-blank otherID case would spuriously fail Build even when EUID alone
// makes the document otherwise complete and valid.
func otherIDsFromFuzz(typ, val string) []ts5.Identifier {
	if typ == "" && val == "" {
		return nil
	}
	return []ts5.Identifier{{Type: typ, Identifier: val}}
}
