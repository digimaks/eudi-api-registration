// Package routes (this file): the admin API's structured registration
// endpoint — PUT /clients/{id}/registration maps a self-contained JSON DTO
// (the OpenAPI contract's RegistrationRequest) onto internal/wizard.FormState
// and calls its OWN Build. This handler adds NO validation of its own beyond
// "is this valid JSON" — every ARF TS5 assembly/validation rule (legal
// identity, identifiers, country, credential meta, claim paths, supervisory
// authority, pending-<ulid> intended-use ids) lives exactly once, in
// wizard.FormState.Build, and this admin surface reuses it as-is.
//
// apiRegistrationRequest is a DELIBERATE contract DTO: its own JSON field
// names/shapes (MultiLangText's "text" vs ts5.MultiLangString's "content";
// SupervisoryAuthorityInput's "formUri" vs ts5.SupervisoryAuthority's
// "formURI"), decoupled from both ts5 and wizard.FormState, so the wire
// contract can evolve independently of either. What IS and is NOT reused from
// wizard.FormState's own form-handling code is explained at toFormState's doc
// comment below.
package routes

import (
	"encoding/json"
	"time"

	"azugo.io/azugo"

	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/dativa-lv/eudi-api-registration/internal/wizard"
)

// defaultPrivacyPolicyTypeURI is applied when a privacy-policy entry omits an
// explicit type (TS 119 475 Annex B.2.8 vocabulary).
const defaultPrivacyPolicyTypeURI = "http://data.europa.eu/eudi/policy/privacy-policy"

// apiIdentifier is the OpenAPI contract's RegistrationRequest otherIds entry
// shape ({type, identifier}) — happens to coincide with ts5.Identifier's own
// JSON shape today, but is kept as this contract's OWN type per this file's
// package doc comment (never assume the two stay identical just because they
// do right now).
type apiIdentifier struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// apiMultiLangText is the OpenAPI contract's MultiLangText:
// [ARF TS5 v1.3 §2.4.5]-shaped, but with this contract's OWN field name "text"
// (ts5.MultiLangString calls the same thing "content" — decoupled
// deliberately, see the package doc comment).
type apiMultiLangText struct {
	Lang string `json:"lang"`
	Text string `json:"text"`
}

// apiPrivacyPolicy is the OpenAPI contract's PrivacyPolicyInput: a bare URI —
// this contract never collects a policy TYPE (unlike ts5.Policy, which
// carries one). toTS5Policies below always assigns the default privacy-policy
// type URI (the defaultPrivacyPolicyTypeURI constant — see toFormState's doc
// comment for why).
type apiPrivacyPolicy struct {
	URI string `json:"uri"`
}

// apiCredential is the OpenAPI contract's CredentialInput — maps
// field-for-field onto wizard.CredentialForm (identical field set), so
// toWizardCredentials below is a plain reshape with no business logic of its
// own: wizard.CredentialForm.build() (invoked transitively by FormState.Build)
// is what actually validates the format, checks doctype/vct cardinality,
// validates claim paths, and assembles the [OID4VP §6.1] meta object — none of
// that is duplicated here.
type apiCredential struct {
	Format         string     `json:"format"`
	DoctypesOrVCTs []string   `json:"doctypesOrVcts"`
	AllClaims      bool       `json:"allClaims,omitempty"`
	Claims         [][]string `json:"claims,omitempty"`
}

// apiIntendedUse is the OpenAPI contract's IntendedUseInput.
type apiIntendedUse struct {
	Purpose       []apiMultiLangText `json:"purpose"`
	PrivacyPolicy []apiPrivacyPolicy `json:"privacyPolicy"`
	Credentials   []apiCredential    `json:"credentials"`
}

// apiSupervisory is the OpenAPI contract's SupervisoryAuthorityInput — note
// the "formUri" field name (this contract's own casing), vs
// ts5.SupervisoryAuthority's "formURI".
type apiSupervisory struct {
	Name    string   `json:"name,omitempty"`
	Country string   `json:"country"`
	Email   []string `json:"email,omitempty"`
	Phone   []string `json:"phone,omitempty"`
	FormURI []string `json:"formUri,omitempty"`
}

// apiRegistrationRequest is PUT /api/clients/{id}/registration's wire body
// (the OpenAPI contract's RegistrationRequest). See this file's package doc
// comment for why it is its own type rather than ts5/wizard structs decoded
// directly. Every field-presence/business rule beyond "is
// this valid JSON" (legalPerson needs >= 1 legalName, at least one
// identifier, country shape, intended-use/credential/claim shape,
// supervisory-authority contact, ...) is enforced ONLY by
// wizard.FormState.Build once toFormState maps this onto it — this type has
// no validation methods of its own.
type apiRegistrationRequest struct {
	LegalKind            string           `json:"legalKind"`
	LegalName            []string         `json:"legalName,omitempty"`
	GivenName            string           `json:"givenName,omitempty"`
	FamilyName           string           `json:"familyName,omitempty"`
	EUID                 string           `json:"euid,omitempty"`
	OtherIDs             []apiIdentifier  `json:"otherIds,omitempty"`
	Country              string           `json:"country"`
	Email                []string         `json:"email,omitempty"`
	InfoURI              []string         `json:"infoUri,omitempty"`
	SupportURI           []string         `json:"supportUri,omitempty"`
	TradeName            string           `json:"tradeName,omitempty"`
	IntendedUses         []apiIntendedUse `json:"intendedUses"`
	SupervisoryAuthority apiSupervisory   `json:"supervisoryAuthority"`
	IsPSB                bool             `json:"isPsb,omitempty"`
}

// apiRegistrationResult is PUT .../registration's 200 response (the OpenAPI
// contract's RegistrationResult): State is read back via GetClientFull AFTER
// the save — this endpoint never itself changes lifecycle state (the
// contract's own description says so), but the response still reports whatever
// state the client is CURRENTLY in.
type apiRegistrationResult struct {
	ID           string `json:"id"`
	State        string `json:"state"`
	IntendedUses int    `json:"intendedUses"`
}

// toFormState maps apiRegistrationRequest onto wizard.FormState/
// IntendedUseForm/CredentialForm. This is a RESHAPE, not a re-validation:
// every business rule lives in wizard.FormState.Build (called by the handler
// immediately after this), never here.
//
// The input is already structured JSON (arrays of objects), so the mapping is
// a direct field copy — there is no parallel-slice line-splitting/zipping to
// do. The one place business logic could otherwise creep in is the
// default-privacy-policy-type substitution: toTS5Policies below assigns the
// defaultPrivacyPolicyTypeURI constant whenever a policy entry carries no type
// of its own. Country-code TrimSpace+ToUpper normalization is deliberately NOT
// done here: this contract's country/supervisoryAuthority.country fields
// already declare an exact `^[A-Z]{2}$` pattern, so a machine caller is
// expected to already send the declared shape, and wizard.FormState.Build's
// own validateCountryCode remains the single authority on what actually
// passes.
func (req apiRegistrationRequest) toFormState() wizard.FormState {
	otherIDs := make([]ts5.Identifier, 0, len(req.OtherIDs))
	for _, oid := range req.OtherIDs {
		otherIDs = append(otherIDs, ts5.Identifier{Type: oid.Type, Identifier: oid.Identifier})
	}

	intendedUses := make([]wizard.IntendedUseForm, 0, len(req.IntendedUses))
	for _, iu := range req.IntendedUses {
		intendedUses = append(intendedUses, wizard.IntendedUseForm{
			Purpose:       toTS5MultiLang(iu.Purpose),
			PrivacyPolicy: toTS5Policies(iu.PrivacyPolicy),
			Credentials:   toWizardCredentials(iu.Credentials),
		})
	}

	return wizard.FormState{
		LegalKind:    req.LegalKind,
		LegalName:    req.LegalName,
		GivenName:    req.GivenName,
		FamilyName:   req.FamilyName,
		EUID:         req.EUID,
		OtherIDs:     otherIDs,
		Country:      req.Country,
		Email:        req.Email,
		InfoURI:      req.InfoURI,
		SupportURI:   req.SupportURI,
		TradeName:    req.TradeName,
		IntendedUses: intendedUses,
		Supervisory: ts5.SupervisoryAuthority{
			Name:    req.SupervisoryAuthority.Name,
			Country: req.SupervisoryAuthority.Country,
			Email:   req.SupervisoryAuthority.Email,
			Phone:   req.SupervisoryAuthority.Phone,
			FormURI: req.SupervisoryAuthority.FormURI,
		},
		IsPSB: req.IsPSB,
	}
}

// toTS5MultiLang maps [](lang,text) onto ts5.MultiLangString, renaming this
// contract's "text" field to ts5's own "Content" field.
func toTS5MultiLang(in []apiMultiLangText) []ts5.MultiLangString {
	if len(in) == 0 {
		return nil
	}
	out := make([]ts5.MultiLangString, 0, len(in))
	for _, m := range in {
		out = append(out, ts5.MultiLangString{Lang: m.Lang, Content: m.Text})
	}
	return out
}

// toTS5Policies maps [](uri) onto ts5.Policy, always assigning the default
// privacy-policy type URI (see toFormState's doc comment for why).
func toTS5Policies(in []apiPrivacyPolicy) []ts5.Policy {
	if len(in) == 0 {
		return nil
	}
	out := make([]ts5.Policy, 0, len(in))
	for _, p := range in {
		out = append(out, ts5.Policy{Type: defaultPrivacyPolicyTypeURI, PolicyURI: p.URI})
	}
	return out
}

// toWizardCredentials maps apiCredential onto wizard.CredentialForm
// field-for-field — see apiCredential's doc comment for why this carries no
// conversion logic of its own.
func toWizardCredentials(in []apiCredential) []wizard.CredentialForm {
	if len(in) == 0 {
		return nil
	}
	out := make([]wizard.CredentialForm, 0, len(in))
	for _, c := range in {
		out = append(out, wizard.CredentialForm{
			Format:         c.Format,
			DoctypesOrVCTs: c.DoctypesOrVCTs,
			AllClaims:      c.AllClaims,
			Claims:         c.Claims,
		})
	}
	return out
}

// apiSetRegistration handles PUT /api/clients/{id}/registration (the OpenAPI
// contract's setClientRegistration): decode the contract DTO, map it onto
// wizard.FormState, run wizard.FormState.Build, then persist via
// SaveWRPDocument. The ENTIRE document is given in one request — there is no
// server-side FormState accumulated across steps — and any previously stored
// document/intended-use projection is fully replaced (SaveWRPDocument's own
// replace-all-upsert semantics — never a partial merge, matching the OpenAPI
// description).
//
// A malformed JSON body is err:api:invalidBody (400). A Build validation
// failure (missing intended use, bad claim path, non-https privacy policy,
// incomplete supervisory authority, ...) is err:api:registrationInvalid
// (422) — Build's error message describes document SHAPE (which rule failed),
// never an attribute VALUE, so it is safe to return verbatim as the problem
// detail; the raw request body is never echoed anywhere.
func (r *router) apiSetRegistration(ctx *azugo.Context) {
	var req apiRegistrationRequest
	if err := json.Unmarshal(ctx.Request().Body(), &req); err != nil {
		ctx.Error(pkerrors.NewProblem("err:api:invalidBody", pkerrors.WithDetail("body is not valid JSON")))
		return
	}

	fs := req.toFormState()
	doc, ius, err := fs.Build(time.Now)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:api:registrationInvalid", pkerrors.WithDetail(err.Error())))
		return
	}

	docJSON, err := json.Marshal(doc)
	if err != nil {
		ctx.Error(err)
		return
	}

	id := ctx.Params.String("id")
	if err := r.Store().SaveWRPDocument(ctx, id, docJSON, ius, "api"); err != nil {
		ctx.Error(err)
		return
	}

	full, err := r.Store().GetClientFull(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.JSON(apiRegistrationResult{ID: id, State: full.Status, IntendedUses: len(ius)})
}
