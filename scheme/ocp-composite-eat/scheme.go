// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/ear"
	"github.com/veraison/services/handler"
	"github.com/veraison/services/plugin"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
	"github.com/veraison/services/vts/appraisal"
)

const (
	SchemeName        = "OCP_COMPOSITE_EAT"
	EvidenceMediaType = "application/eat-bun+cbor"
)

type Handler struct {
	engine *Engine
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Fini() error {
	return nil
}

func (h *Handler) Init(params *plugin.Parameters) error {
	if params == nil {
		return errors.New("composite EAT scheme configuration is missing")
	}
	platformCoRIM, err := params.DefaultGetString("platform-corim", "")
	if err != nil {
		return fmt.Errorf("platform-corim: %w", err)
	}
	classPackage, err := params.DefaultGetString("class-package", "")
	if err != nil {
		return fmt.Errorf("class-package: %w", err)
	}
	endorsementRootsPath, err := params.GetString("endorsement-roots")
	if err != nil {
		return fmt.Errorf("endorsement-roots: %w", err)
	}
	evidenceRootsPath, err := params.GetString("evidence-roots")
	if err != nil {
		return fmt.Errorf("evidence-roots: %w", err)
	}
	evidenceProfile, err := params.DefaultGetString("composite-eat-profile", CompositeEATProfile)
	if err != nil {
		return err
	}
	if err := manifest.ValidateProfileURI(evidenceProfile); err != nil {
		return err
	}
	caliptraCompatibility, err := params.DefaultGetBool("caliptra-compatibility", false)
	if err != nil {
		return fmt.Errorf("caliptra-compatibility: %w", err)
	}
	nativeSPDM, err := params.DefaultGetBool("native-spdm", false)
	if err != nil {
		return fmt.Errorf("native-spdm: %w", err)
	}
	spdm10ReversedECDSA, err := params.DefaultGetBool("spdm-1.0-reversed-ecdsa", false)
	if err != nil {
		return fmt.Errorf("spdm-1.0-reversed-ecdsa: %w", err)
	}
	endorsementRoots, err := LoadPEMRoots(endorsementRootsPath)
	if err != nil {
		return err
	}
	evidenceRoots, err := LoadPEMRoots(evidenceRootsPath)
	if err != nil {
		return err
	}
	provider, err := LoadEndorsementProvider(platformCoRIM, classPackage, endorsementRoots, evidenceProfile, time.Now())
	if err != nil {
		return err
	}
	h.engine = &Engine{
		CompositeEATProfile: evidenceProfile,
		EndorsementProvider: provider, EvidenceRoots: evidenceRoots,
		EnableNativeSPDM:            nativeSPDM,
		EnableCaliptraCompatibility: caliptraCompatibility,
		AllowSPDM10ReversedECDSA:    spdm10ReversedECDSA,
		Limits:                      DefaultLimits(), Now: time.Now,
	}
	return nil
}

func (h *Handler) GetName() string {
	return handler.PluginNameFromScheme(SchemeName)
}

func (h *Handler) GetAttestationScheme() string {
	return SchemeName
}

func (h *Handler) GetSupportedMediaTypes() map[string][]string {
	return map[string][]string{
		"provisioning": {},
		"verification": {EvidenceMediaType},
	}
}

func (h *Handler) GetSupportedProvisioningMediaTypes() []string {
	return nil
}

func (h *Handler) GetSupportedVerificationMediaTypes() []string {
	return []string{EvidenceMediaType}
}

func (h *Handler) UsesExternalEndorsements() bool {
	return false
}

func (h *Handler) ValidateCorim(*corim.UnsignedCorim) (*handler.ValidateCorimResponse, error) {
	return &handler.ValidateCorimResponse{IsValid: false, Message: "configured endorsement providers do not accept provisioning updates"}, nil
}

func (h *Handler) GetTrustAnchorIDs(*appraisal.Evidence) ([]*comid.Environment, error) {
	return nil, nil
}

func (h *Handler) GetReferenceValueIDs([]*comid.KeyTriple, map[string]any) ([]*comid.Environment, error) {
	return nil, nil
}

func (h *Handler) ExtractClaims(evidence *appraisal.Evidence, _ []*comid.KeyTriple) (map[string]any, error) {
	if h.engine == nil {
		return nil, errors.New("composite EAT scheme is not initialized")
	}
	if evidence.MediaType != EvidenceMediaType {
		return nil, handler.BadEvidence("wrong media type %q", evidence.MediaType)
	}
	report, err := h.engine.Verify(evidence.Data, evidence.Nonce)
	if err != nil {
		return nil, handler.BadEvidence(err)
	}
	return reportToMap(report)
}

func (h *Handler) ValidateEvidenceIntegrity(
	*appraisal.Evidence,
	[]*comid.KeyTriple,
	[]*comid.ValueTriple,
) error {
	return nil
}

func (h *Handler) AppraiseClaims(claims map[string]any, _ []*comid.ValueTriple) (*ear.AttestationResult, error) {
	report, err := mapToReport(claims)
	if err != nil {
		return nil, fmt.Errorf("decode verified Composite EAT report: %w", err)
	}
	result := handler.CreateAttestationResult(SchemeName)
	setEARAppraisal(result.Submods[SchemeName], ComponentResult{
		Status: report.Status, Reason: report.Reason, Dimensions: aggregateDimensions(report),
	}, map[string]any{
		"bundle-digest": report.BundleDigest, "snapshot-digest": report.SnapshotDigest,
		"corim-id": report.CoRIMID, "lead-ueid": report.LeadUEID,
		"endorsement-sources": report.SourceDigests, "enrollment-id": report.EnrollmentID,
		"enrollment-revision": report.EnrollmentRevision, "platform-variant": report.Variant,
		"component-carriage": report.ComponentCarriage, "carriage-compatibility-used": report.CompatibilityUsed,
	})
	lead := ear.NewAppraisal()
	setEARAppraisal(lead, report.Lead, nil)
	result.Submods["lead"] = lead
	for label, component := range report.Components {
		entry := ear.NewAppraisal()
		setEARAppraisal(entry, component, nil)
		result.Submods[label] = entry
	}
	result.UpdateStatusFromTrustVector()
	return result, nil
}

func aggregateDimensions(report *Report) ComponentDimensions {
	result := report.Lead.Dimensions
	for _, component := range report.Components {
		mergeDimension := func(target *DimensionResult, source DimensionResult) {
			if outcomeSeverity(source.Status) > outcomeSeverity(target.Status) {
				*target = source
			}
		}
		mergeDimension(&result.EvidenceProtection, component.Dimensions.EvidenceProtection)
		mergeDimension(&result.Freshness, component.Dimensions.Freshness)
		mergeDimension(&result.Identity, component.Dimensions.Identity)
		mergeDimension(&result.Composition, component.Dimensions.Composition)
		mergeDimension(&result.Measurements, component.Dimensions.Measurements)
		mergeDimension(&result.Policy, component.Dimensions.Policy)
	}
	return result
}

func outcomeSeverity(outcome Outcome) int {
	switch outcome {
	case OutcomeFail:
		return 3
	case OutcomeUnsupported:
		return 2
	case OutcomeIndeterminate:
		return 1
	default:
		return 0
	}
}

func setEARAppraisal(target *ear.Appraisal, component ComponentResult, annotations map[string]any) {
	switch component.Dimensions.Identity.Status {
	case OutcomePass:
		target.TrustVector.InstanceIdentity = ear.TrustworthyInstanceClaim
	case OutcomeFail:
		target.TrustVector.InstanceIdentity = ear.UntrustworthyInstanceClaim
	}
	switch component.Dimensions.Measurements.Status {
	case OutcomePass:
		target.TrustVector.Executables = ear.ApprovedRuntimeClaim
	case OutcomeFail:
		target.TrustVector.Executables = ear.UnrecognizedRuntimeClaim
	}
	switch component.Dimensions.Policy.Status {
	case OutcomePass:
		target.TrustVector.Configuration = ear.ApprovedConfigClaim
	case OutcomeFail:
		target.TrustVector.Configuration = ear.UnsafeConfigClaim
	}
	policyClaims := map[string]any{
		"outcome": string(component.Status), "reason": component.Reason,
		"dimensions": component.Dimensions,
	}
	target.VeraisonPolicyClaims = &policyClaims
	if annotations != nil {
		target.VeraisonAnnotatedEvidence = &annotations
	}
	target.UpdateStatusFromTrustVector()
	if (component.Status != OutcomePass || dimensionsStatus(component.Dimensions) != OutcomePass) && *target.Status < ear.TrustTierWarning {
		*target.Status = ear.TrustTierWarning
	}
}

func reportToMap(report *Report) (map[string]any, error) {
	data, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func mapToReport(claims map[string]any) (*Report, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	if report.Status != OutcomePass && report.Status != OutcomeFail {
		return nil, fmt.Errorf("invalid report status %q", report.Status)
	}
	return &report, nil
}

func LoadPEMRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read roots %q: %w", path, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("roots %q contain no PEM certificates", path)
	}
	return roots, nil
}

func CheckEARNonce(result *ear.AttestationResult, expected []byte) error {
	if len(expected) != 32 || result.Nonce == nil {
		return errors.New("missing or invalid session nonce")
	}
	actual, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(*result.Nonce, "="))
	if err != nil || !bytes.Equal(actual, expected) {
		return errors.New("signed EAR nonce does not match the session")
	}
	return nil
}
