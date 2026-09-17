// Package wizard assembles and validates the ARF TS6 / CIR 2025/848 Annex I
// self-registration data set into a valid ts5.WalletRelyingParty document plus
// eudi-api-registration's own scope-projection JSON
// (registrydb.RegisteredCredentialJSON / registrydb.IntendedUse) that the
// session service reads at session time.
//
// ts5 (github.com/gmb-eudi/go-eudi-rpcert/ts5) is the authoritative local
// model: the ARF TS5 JSON schema itself is NOT vendored, and ts5's structs
// mirror it field-for-field per that package's doc.go. This package never
// invents its own document shape — Build only ever populates ts5 struct
// fields, and its whole validation surface is "what the ts5 model contract
// enforces that can be checked without a live registrar".
//
// // ARF TS6 / CIR 2025/848 Annex I (unverified upstream ref — ARF TS6 text
// // not vendored; model authority: rpcert/ts5)
package wizard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/gmb-eudi/go-eudi-rpcert/ts5"

	"github.com/dativa-lv/eudi-api-registration/internal/registrydb"
)

// euidTypeURI is the [ARF TS5 v1.3 §2.4.2.1] preferred identifier type — EUID
// (European Unique Identifier), from TS 119 475 Annex B.2.5's identifier
// type URI namespace. Build always places an EUID identifier FIRST in the
// resulting list when one is given.
//
// // [ARF TS5 v1.3 §2.4.2.1] EUID preferred
const euidTypeURI = "http://data.europa.eu/eudi/id/EUID"

// pendingIUPrefix marks a wizard-minted intended-use identifier as a
// placeholder: each ts5.IntendedUse gets a wizard-minted
// IntendedUseIdentifier placeholder (pending-<ulid>), replaced with the
// registrar-assigned id once known.
const pendingIUPrefix = "pending-"

// Supported credential formats ([OID4VP §6.1] / [ARF TS5 v1.3 §2.4.4]). Build rejects
// anything else with ErrCredentialFormat — "unknown credential format =
// reject, never fall through" discipline (this package has no crypto policy
// of its own; go-eudi-crypto owns that).
const (
	FormatMDoc  = "mso_mdoc"
	FormatSDJWT = "dc+sd-jwt"
)

// Sentinel validation errors. Build wraps one of these with positional
// detail (which intended use / credential / claim) so callers can
// errors.Is() without parsing message text; none of these — nor any message
// built from them — ever carries a wallet attribute VALUE: they describe
// registration-time form/structure choices (formats, URLs, language tags),
// never verified credential data.
var (
	ErrLegalIdentity        = errors.New("wizard: exactly one of legalPerson/naturalPerson is required")
	ErrIdentifier           = errors.New("wizard: at least one identifier is required")
	ErrCountry              = errors.New("wizard: country must be an ISO 3166-1 alpha-2 code")
	ErrIntendedUse          = errors.New("wizard: at least one intended use is required")
	ErrPurpose              = errors.New("wizard: intended use requires at least one purpose (language + content)")
	ErrPrivacyPolicy        = errors.New("wizard: intended use requires at least one privacy policy with an absolute https policyURI")
	ErrCredential           = errors.New("wizard: intended use requires at least one valid credential")
	ErrCredentialFormat     = errors.New("wizard: unsupported credential format")
	ErrClaimPath            = errors.New("wizard: malformed claim path")
	ErrSupervisoryAuthority = errors.New("wizard: supervisoryAuthority country and a contact channel are required")
)

// FormState holds the structured registration input Build assembles and
// validates into the ts5.WalletRelyingParty document.
type FormState struct {
	LegalKind                         string // "legalPerson" | "naturalPerson"
	LegalName                         []string
	GivenName, FamilyName             string
	EUID                              string // preferred identifier ([ARF TS5 v1.3 §2.4.2.1]); type URI http://data.europa.eu/eudi/id/EUID
	OtherIDs                          []ts5.Identifier
	Country                           string
	Email, Phone, InfoURI, SupportURI []string
	TradeName                         string
	SrvDescription                    []ts5.MultiLangString
	IntendedUses                      []IntendedUseForm
	Supervisory                       ts5.SupervisoryAuthority
	IsPSB                             bool
}

// IntendedUseForm is one requested intended use ([ARF TS5 v1.3 §2.4.3]).
type IntendedUseForm struct {
	Purpose       []ts5.MultiLangString // MultiLang purpose (≥1 lang)
	PrivacyPolicy []ts5.Policy          // ≥1 policy URI
	Credentials   []CredentialForm      // format + doctype/vct + claim paths or all-claims
}

// CredentialForm is this package's own addition — a deliberately practical
// subset of ts5.Credential (IntendedUseForm.Credentials is "format +
// doctype/vct + claim paths or all-claims"):
//
//   - DoctypesOrVCTs holds one value for mso_mdoc (OID4VP Appendix B.2.3:
//     doctype_value is singular — exactly one is required, see build())
//     or one-or-more for dc+sd-jwt (Appendix B.3.5: vct_values is an array).
//   - Claims holds each claim path as a slice of STRING segments only, so it
//     never offers array-index or wildcard path elements even though
//     ts5.ClaimPath supports them ([OID4VP §7]). AllClaims true means the
//     wizard collected NO claims list for this credential — Claims must then
//     be empty, and the registered attestation is described by its schema or
//     rulebook rather than by an enumerated claim list ([ARF TS5 v1.3 §2.4.4]
//     gives `claims` cardinality [1..*], so it is either absent or non-empty).
//     This is a REGISTRATION document, not a DCQL query: in a query an absent
//     claims list means the opposite ([OID4VP §6.4.1] — only the claims that
//     are mandatory to present).
type CredentialForm struct {
	Format         string
	DoctypesOrVCTs []string
	AllClaims      bool
	Claims         [][]string
}

// Build assembles and validates the WalletRelyingParty document.
// Validation mirrors the ARF TS5 model contract enforceable locally:
//
//	exactly one of LegalPerson/NaturalPerson; ≥1 identifier (EUID preferred);
//	country ISO 3166-1; every intended use: ≥1 purpose lang, ≥1 privacy
//	policy with absolute https policyURI, ≥1 credential with format ∈
//	{mso_mdoc, dc+sd-jwt} and valid claim paths; supervisoryAuthority
//	country+contact present; NO address fields anywhere (the ts5 decoders
//	reject ErrAddressPresent — the wizard never collects them: FormState has
//	no address field at all, by construction).
//
// Round-trip check (wizard_test.go): marshal → ts5.DecodeSignedWRP-compatible
// json.Unmarshal into ts5.WalletRelyingParty must succeed with no field loss.
//
// On any validation failure Build returns (nil, nil, err) — never a
// partially-built document (invalid input yields an error, not a malformed
// document). now defaults to time.Now when nil.
func (f *FormState) Build(now func() time.Time) (*ts5.WalletRelyingParty, []registrydb.IntendedUse, error) {
	if now == nil {
		now = time.Now
	}

	wrp := &ts5.WalletRelyingParty{
		TradeName:  f.TradeName,
		SupportURI: nonEmpty(f.SupportURI),
		IsPSB:      f.IsPSB,
		Country:    f.Country,
		Email:      nonEmpty(f.Email),
		Phone:      nonEmpty(f.Phone),
		InfoURI:    nonEmpty(f.InfoURI),
	}
	if len(f.SrvDescription) > 0 {
		// ts5.WalletRelyingParty.SrvDescription is [][]MultiLangString (ARF
		// TS5's own schema shape — see model.go's doc comment); FormState
		// collects a single flat list, wrapped here as the one "language
		// group" the wizard produces.
		wrp.SrvDescription = [][]ts5.MultiLangString{append([]ts5.MultiLangString(nil), f.SrvDescription...)}
	}

	if err := f.applyLegalIdentity(wrp); err != nil {
		return nil, nil, err
	}

	if err := validateCountryCode(f.Country); err != nil {
		return nil, nil, err
	}

	ids, err := f.identifiers()
	if err != nil {
		return nil, nil, err
	}
	wrp.Identifiers = ids

	if err := validateSupervisoryAuthority(f.Supervisory); err != nil {
		return nil, nil, err
	}
	wrp.SupervisoryAuthority = f.Supervisory

	docIUs, projections, err := f.buildIntendedUses(now)
	if err != nil {
		return nil, nil, err
	}
	wrp.IntendedUse = docIUs

	return wrp, projections, nil
}

// applyLegalIdentity enforces "exactly one of LegalPerson/NaturalPerson"
// (TS 119 475 Annex B.2.2/B.2.3/B.2.4) and sets the corresponding field on
// wrp. LegalKind is the sole discriminator: any value other than the two
// recognized ones — including "" (neither chosen) and any other string
// (e.g. a caller mistakenly trying to signal "both") — is ErrLegalIdentity.
func (f *FormState) applyLegalIdentity(wrp *ts5.WalletRelyingParty) error {
	switch f.LegalKind {
	case "legalPerson":
		names := nonEmpty(f.LegalName)
		if len(names) == 0 {
			return fmt.Errorf("%w: legalPerson requires at least one legalName", ErrLegalIdentity)
		}
		wrp.LegalPerson = &ts5.LegalPerson{LegalName: names}
		return nil
	case "naturalPerson":
		if f.GivenName == "" || f.FamilyName == "" {
			return fmt.Errorf("%w: naturalPerson requires givenName and familyName", ErrLegalIdentity)
		}
		wrp.NaturalPerson = &ts5.NaturalPerson{GivenName: f.GivenName, FamilyName: f.FamilyName}
		return nil
	default:
		return fmt.Errorf("%w: legalKind must be \"legalPerson\" or \"naturalPerson\", got %q", ErrLegalIdentity, f.LegalKind)
	}
}

// identifiers assembles the ts5.Identifier list: EUID FIRST when present
// ([ARF TS5 v1.3 §2.4.2.1] preferred), then OtherIDs in the order given. At least one
// identifier — EUID or an OtherIDs entry — is required.
//
// // [ARF TS5 v1.3 §2.4.2.1] EUID preferred
func (f *FormState) identifiers() ([]ts5.Identifier, error) {
	ids := make([]ts5.Identifier, 0, 1+len(f.OtherIDs))
	if f.EUID != "" {
		ids = append(ids, ts5.Identifier{Type: euidTypeURI, Identifier: f.EUID})
	}
	for i, other := range f.OtherIDs {
		if other.Type == "" || other.Identifier == "" {
			return nil, fmt.Errorf("%w: otherIDs[%d] requires both type and identifier", ErrIdentifier, i)
		}
		ids = append(ids, other)
	}
	if len(ids) == 0 {
		return nil, ErrIdentifier
	}
	return ids, nil
}

// validateCountryCode checks the one thing enforceable locally without
// vendoring the full ISO 3166-1 table: exactly two uppercase ASCII letters.
// The ARF TS5 JSON schema itself is not vendored either (package doc comment),
// so this is the locally-checkable subset for "country ISO 3166-1"; a live
// registrar (or the ARF-mandated Member State list) would reject an
// unassigned-but-well-formed code, which is out of this package's reach.
func validateCountryCode(c string) error {
	if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
		return fmt.Errorf("%w: got %q", ErrCountry, c)
	}
	return nil
}

// validateSupervisoryAuthority enforces "supervisoryAuthority country+contact
// present": a well-formed country code plus at least one contact channel
// (email, phone, or a formURI to file a report).
func validateSupervisoryAuthority(sa ts5.SupervisoryAuthority) error {
	if err := validateCountryCode(sa.Country); err != nil {
		return fmt.Errorf("%w: country %w", ErrSupervisoryAuthority, err)
	}
	if len(sa.Email) == 0 && len(sa.Phone) == 0 && len(sa.FormURI) == 0 {
		return fmt.Errorf("%w: at least one contact channel (email/phone/formURI) is required", ErrSupervisoryAuthority)
	}
	return nil
}

// buildIntendedUses validates and converts every IntendedUseForm into both
// the ts5.IntendedUse the document carries and the registrydb.IntendedUse
// scope projection SaveWRPDocument persists.
func (f *FormState) buildIntendedUses(now func() time.Time) ([]ts5.IntendedUse, []registrydb.IntendedUse, error) {
	if len(f.IntendedUses) == 0 {
		return nil, nil, ErrIntendedUse
	}

	// ts5.IntendedUse.CreatedAt: ISO 8601-1 YYYY-MM-DD (model.go doc comment).
	createdAt := now().UTC().Format("2006-01-02")

	docIUs := make([]ts5.IntendedUse, 0, len(f.IntendedUses))
	projections := make([]registrydb.IntendedUse, 0, len(f.IntendedUses))

	for i, iuf := range f.IntendedUses {
		if err := validatePurpose(iuf.Purpose); err != nil {
			return nil, nil, fmt.Errorf("%w (intended use %d)", err, i)
		}
		if err := validatePrivacyPolicy(iuf.PrivacyPolicy); err != nil {
			return nil, nil, fmt.Errorf("%w (intended use %d)", err, i)
		}
		if len(iuf.Credentials) == 0 {
			return nil, nil, fmt.Errorf("%w (intended use %d has no credentials)", ErrCredential, i)
		}

		creds := make([]ts5.Credential, 0, len(iuf.Credentials))
		projCreds := make([]registrydb.RegisteredCredentialJSON, 0, len(iuf.Credentials))
		for j, cf := range iuf.Credentials {
			cred, projCred, err := cf.build()
			if err != nil {
				return nil, nil, fmt.Errorf("%w (intended use %d credential %d)", err, i, j)
			}
			creds = append(creds, cred)
			projCreds = append(projCreds, projCred)
		}

		iuID := pendingIUPrefix + ulid.Make().String()
		docIUs = append(docIUs, ts5.IntendedUse{
			Purpose:               iuf.Purpose,
			PrivacyPolicy:         iuf.PrivacyPolicy,
			IntendedUseIdentifier: iuID,
			CreatedAt:             createdAt,
			Credentials:           creds,
		})

		purposeJSON, err := json.Marshal(iuf.Purpose)
		if err != nil {
			return nil, nil, fmt.Errorf("wizard: marshal purpose: %w", err)
		}
		projections = append(projections, registrydb.IntendedUse{
			IntendedUseID: iuID,
			Purpose:       purposeJSON,
			Credentials:   projCreds,
		})
	}

	return docIUs, projections, nil
}

// validatePurpose enforces "≥1 purpose lang" with both lang and content
// present on every entry (an empty lang or content is not a usable
// multi-lang purpose statement).
func validatePurpose(purpose []ts5.MultiLangString) error {
	if len(purpose) == 0 {
		return ErrPurpose
	}
	for _, p := range purpose {
		if p.Lang == "" || p.Content == "" {
			return fmt.Errorf("%w: every purpose entry needs a lang and content", ErrPurpose)
		}
	}
	return nil
}

// validatePrivacyPolicy enforces "≥1 privacy policy with an absolute https
// policyURI".
func validatePrivacyPolicy(policies []ts5.Policy) error {
	if len(policies) == 0 {
		return ErrPrivacyPolicy
	}
	for _, p := range policies {
		if err := validateHTTPSPolicyURI(p.PolicyURI); err != nil {
			return err
		}
	}
	return nil
}

// validateHTTPSPolicyURI enforces "an absolute https policyURI": url.Parse
// alone accepts relative references and non-http(s) schemes without error,
// so Scheme/Host are checked explicitly rather than trusting a bare
// parse-without-error.
func validateHTTPSPolicyURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: policyURI %q must be an absolute https URL", ErrPrivacyPolicy, raw)
	}
	return nil
}

// build validates cf and converts it into both the ts5.Credential the
// document carries and its registrydb.RegisteredCredentialJSON scope
// projection. The two conversions are built together, from the same
// validated fields, so they can never describe two different credentials.
func (cf CredentialForm) build() (ts5.Credential, registrydb.RegisteredCredentialJSON, error) {
	if cf.Format != FormatMDoc && cf.Format != FormatSDJWT {
		return ts5.Credential{}, registrydb.RegisteredCredentialJSON{}, fmt.Errorf("%w: %q", ErrCredentialFormat, cf.Format)
	}

	doctypesOrVCTs := nonEmpty(cf.DoctypesOrVCTs)
	if len(doctypesOrVCTs) == 0 {
		return ts5.Credential{}, registrydb.RegisteredCredentialJSON{}, fmt.Errorf("%w: at least one doctype/vct value is required", ErrCredential)
	}

	meta, err := buildMeta(cf.Format, doctypesOrVCTs)
	if err != nil {
		return ts5.Credential{}, registrydb.RegisteredCredentialJSON{}, err
	}

	var claims []ts5.Claim
	var projClaims [][]any
	if !cf.AllClaims {
		if len(cf.Claims) == 0 {
			return ts5.Credential{}, registrydb.RegisteredCredentialJSON{}, fmt.Errorf("%w: all_claims=false requires at least one claim path", ErrClaimPath)
		}
		claims = make([]ts5.Claim, 0, len(cf.Claims))
		projClaims = make([][]any, 0, len(cf.Claims))
		for k, segs := range cf.Claims {
			path, err := toClaimPath(segs)
			if err != nil {
				return ts5.Credential{}, registrydb.RegisteredCredentialJSON{}, fmt.Errorf("%w: claim %d: %w", ErrClaimPath, k, err)
			}
			claims = append(claims, ts5.Claim{Path: path})
			projClaims = append(projClaims, []any(path))
		}
	}

	cred := ts5.Credential{Format: cf.Format, Meta: meta, Claims: claims}
	proj := registrydb.RegisteredCredentialJSON{
		Format:         cf.Format,
		DoctypesOrVCTs: doctypesOrVCTs,
		AllClaims:      cf.AllClaims,
		Claims:         projClaims,
	}
	return cred, proj, nil
}

// toClaimPath converts the wizard's string-segment path (CredentialForm's
// doc comment: no array-index/wildcard support) into a ts5.ClaimPath — a
// non-empty slice of non-empty string keys.
func toClaimPath(segs []string) (ts5.ClaimPath, error) {
	if len(segs) == 0 {
		return nil, errors.New("path must have at least one segment")
	}
	path := make(ts5.ClaimPath, 0, len(segs))
	for i, s := range segs {
		if s == "" {
			return nil, fmt.Errorf("segment %d is empty", i)
		}
		path = append(path, s)
	}
	return path, nil
}

// buildMeta assembles the [OID4VP §6.1] per-format meta object
// (ts5.Credential.Meta's doc comment): mso_mdoc carries exactly ONE
// doctype_value (singular — OID4VP Appendix B.2.3; go-eudi-rpcert's own
// wrprc.go metaJSON mirrors this same singular/plural asymmetry); dc+sd-jwt
// carries vct_values as an array (Appendix B.3.5).
func buildMeta(format string, doctypesOrVCTs []string) (json.RawMessage, error) {
	switch format {
	case FormatMDoc:
		if len(doctypesOrVCTs) != 1 {
			return nil, fmt.Errorf("%w: mso_mdoc requires exactly one doctype value, got %d", ErrCredential, len(doctypesOrVCTs))
		}
		return json.Marshal(map[string]string{"doctype_value": doctypesOrVCTs[0]})
	case FormatSDJWT:
		return json.Marshal(map[string][]string{"vct_values": doctypesOrVCTs})
	default:
		// Unreachable: build()'s format check above rejects anything else
		// first. Kept as a fail-closed default rather than a panic — never
		// trust a switch to be exhaustive against future format additions.
		return nil, fmt.Errorf("%w: %s", ErrCredentialFormat, format)
	}
}

// nonEmpty returns ss with empty strings removed, or nil if nothing remains
// — so an all-blank multi-value field yields an omitted JSON key (matching
// the ts5 struct fields' `,omitempty` tags) rather than a JSON array full of
// empty strings.
func nonEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
