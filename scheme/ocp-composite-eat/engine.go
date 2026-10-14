// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/veraison/corim/coev"
	"github.com/veraison/corim/comid"
	"github.com/veraison/services/scheme/ocp-composite-eat/internal/evidencecarriage"
	commonspdm "github.com/veraison/services/scheme/ocp-composite-eat/internal/spdm"
)

type Report struct {
	Status             Outcome                    `json:"status"`
	Reason             string                     `json:"reason"`
	BundleDigest       string                     `json:"bundle-digest"`
	SnapshotDigest     string                     `json:"snapshot-digest"`
	CoRIMID            string                     `json:"corim-id"`
	LeadUEID           string                     `json:"lead-ueid"`
	Lead               ComponentResult            `json:"lead"`
	Components         map[string]ComponentResult `json:"components"`
	SourceDigests      map[string]string          `json:"endorsement-sources,omitempty"`
	EnrollmentID       string                     `json:"enrollment-id,omitempty"`
	EnrollmentRevision string                     `json:"enrollment-revision,omitempty"`
	Variant            string                     `json:"platform-variant,omitempty"`
	ComponentCarriage  map[string]string          `json:"component-carriage,omitempty"`
	CompatibilityUsed  map[string]bool            `json:"carriage-compatibility-used,omitempty"`
}

type Engine struct {
	Snapshot                    *Snapshot
	EndorsementProvider         EndorsementProvider
	EvidenceRoots               *x509.CertPool
	CompositeEATProfile         string
	EnableNativeSPDM            bool
	EnableCaliptraCompatibility bool
	AllowSPDM10ReversedECDSA    bool
	Limits                      Limits
	Now                         func() time.Time
}

func (e *Engine) Verify(bundleBytes, nonce []byte) (*Report, error) {
	if e.Snapshot == nil && e.EndorsementProvider == nil {
		return nil, errors.New("endorsement snapshot is not configured")
	}
	if e.EvidenceRoots == nil {
		return nil, errors.New("evidence roots are not configured")
	}
	currentTime := time.Now()
	if e.Now != nil {
		currentTime = e.Now()
	}
	bundle, err := ParseBundle(bundleBytes, e.Limits)
	if err != nil {
		return nil, err
	}
	lead, err := VerifyMainToken(bundle.MainToken, VerificationContext{
		Roots: e.EvidenceRoots, CurrentTime: currentTime, Nonce: nonce, ExpectedProfile: e.CompositeEATProfile,
	}, e.Limits)
	if err != nil {
		return nil, err
	}
	labels := make([]string, 0, len(lead.Submods))
	for label := range lead.Submods {
		labels = append(labels, label)
	}
	provider := e.EndorsementProvider
	if provider == nil {
		provider = SnapshotProvider{Snapshot: e.Snapshot}
	}
	snapshot, err := provider.Resolve(context.Background(), EndorsementRequest{
		Profile: lead.Profile, LeadUEID: lead.UEID, LeadPublicKey: lead.Leaf.PublicKey,
		ObservedLabels: labels, VerificationTime: currentTime,
	})
	if err != nil {
		return nil, err
	}
	if err := bundle.VerifyDetachedDigests(lead.Submods); err != nil {
		return nil, err
	}

	bundleDigest := sha256.Sum256(bundleBytes)
	report := &Report{
		Status: OutcomePass, Reason: "all mandatory appraisals passed",
		BundleDigest: hex.EncodeToString(bundleDigest[:]), SnapshotDigest: snapshot.Digest,
		CoRIMID: snapshot.CoRIMID, LeadUEID: hex.EncodeToString(lead.UEID),
		SourceDigests: snapshot.SourceDigests, EnrollmentID: snapshot.EnrollmentID, EnrollmentRevision: snapshot.EnrollmentRevision, Variant: snapshot.Variant,
		Lead: ComponentResult{
			Status: OutcomePass, Reason: "Lead identity, signature, nonce, and measurements passed",
			Dimensions: ComponentDimensions{
				EvidenceProtection: passDimension("Lead signature and certificate path passed"),
				Freshness:          passDimension("Lead nonce matches the challenge"),
				Identity:           passDimension("Lead key and UEID are authorized"),
				Composition:        passDimension("Lead commits to the detached component set"),
				Measurements:       DimensionResult{Status: OutcomeIndeterminate, Reason: "measurements not yet appraised"},
				Policy:             passDimension("Composite EAT profile is enabled"),
			},
		},
		Components:        make(map[string]ComponentResult, len(snapshot.Members)),
		ComponentCarriage: make(map[string]string, len(snapshot.Members)),
		CompatibilityUsed: make(map[string]bool, len(snapshot.Members)),
	}

	leadEvidence, err := decodeLeadEvidence(lead.Measurements)
	if err != nil {
		return nil, err
	}
	leadAppraisal := AppraiseMeasurements(snapshot.LeadReferenceValues, leadEvidence)
	if !leadAppraisal.Passed {
		report.Lead.Status = OutcomeFail
		report.Lead.Reason = leadAppraisal.Reason
		report.Lead.Dimensions.Measurements = leadAppraisal.dimension()
		report.Status = OutcomeFail
		report.Reason = "Lead Attester appraisal failed"
	} else {
		report.Lead.Dimensions.Measurements = passDimension(leadAppraisal.Reason)
	}

	if reason := compareMembership(snapshot.Members, lead.Submods); reason != "" {
		report.Status = OutcomeFail
		report.Reason = reason
		report.Lead.Dimensions.Composition = DimensionResult{Status: OutcomeFail, Reason: reason}
	}

	seenIdentities := make(map[string]string)
	labels = make([]string, 0, len(snapshot.Members))
	for label := range snapshot.Members {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		expectation := snapshot.Members[label]
		carriage := expectation.Carriage
		if carriage == "" {
			carriage = "cmw-encoding"
		}
		report.ComponentCarriage[label] = carriage
		report.CompatibilityUsed[label] = expectation.Compatibility
		claimsSet, ok := bundle.DetachedClaimsSets[label]
		if !ok {
			if !expectation.Policy.Required {
				continue
			}
			dimensions := unresolvedDimensions(OutcomeIndeterminate, "component Evidence is unavailable")
			dimensions.Composition = DimensionResult{Status: OutcomeFail, Reason: "required component is missing"}
			report.Components[label] = ComponentResult{Status: OutcomeFail, Reason: "required component is missing", Dimensions: dimensions}
			report.Status = OutcomeFail
			continue
		}
		decoded, err := DecodeNativeEvidence(claimsSet, carriage, expectation.Policy.Evidence.MediaType, e.Limits)
		if err != nil {
			dimensions := unresolvedDimensions(OutcomeIndeterminate, "child authentication did not complete")
			dimensions.EvidenceProtection = DimensionResult{Status: OutcomeFail, Reason: err.Error()}
			report.Components[label] = ComponentResult{Status: OutcomeFail, Reason: err.Error(), Dimensions: dimensions}
			report.Status = OutcomeFail
			continue
		}

		component, result := e.verifyComponent(decoded, nonce, expectation, currentTime)
		if component == nil {
			report.Components[label] = result
			report.Status = OutcomeFail
			continue
		}
		if previous, duplicate := seenIdentities[component.Identity]; duplicate {
			component.Dimensions.Composition = DimensionResult{Status: OutcomeFail, Reason: fmt.Sprintf("identity duplicates %s", previous)}
		} else {
			seenIdentities[component.Identity] = label
		}
		if component.Dimensions.EvidenceProtection.Status != OutcomePass ||
			component.Dimensions.Freshness.Status != OutcomePass ||
			component.Dimensions.Identity.Status != OutcomePass ||
			component.Dimensions.Composition.Status != OutcomePass ||
			component.Dimensions.Policy.Status != OutcomePass {
			componentStatus := dimensionsStatus(component.Dimensions)
			report.Components[label] = ComponentResult{Status: componentStatus, Reason: firstNonPassReason(component.Dimensions), Dimensions: component.Dimensions}
			report.Status = OutcomeFail
			continue
		}
		appraisal := AppraiseMeasurements(expectation.ReferenceValues, component.Measurements)
		if !appraisal.Passed {
			component.Dimensions.Measurements = appraisal.dimension()
		} else {
			component.Dimensions.Measurements = passDimension(appraisal.Reason)
		}
		componentStatus := dimensionsStatus(component.Dimensions)
		componentReason := "native signature, nonce, identity, composition, and measurements passed"
		if componentStatus != OutcomePass {
			componentReason = firstNonPassReason(component.Dimensions)
			report.Status = OutcomeFail
		}
		report.Components[label] = ComponentResult{Status: componentStatus, Reason: componentReason, Dimensions: component.Dimensions}
	}
	if report.Status == OutcomeFail && report.Reason == "all mandatory appraisals passed" {
		report.Reason = "one or more component appraisals failed"
	}
	return report, nil
}

func (e *Engine) verifyComponent(
	decoded *evidencecarriage.DecodedEvidence,
	nonce []byte,
	expectation MemberExpectation,
	currentTime time.Time,
) (*authenticatedComponent, ComponentResult) {
	mediaType := decoded.MediaType
	if mediaType != expectation.Policy.Evidence.MediaType {
		reason := fmt.Sprintf("unsupported native Evidence media type %q for member policy", mediaType)
		return nil, ComponentResult{Status: OutcomeUnsupported, Reason: reason, Dimensions: unresolvedDimensions(OutcomeUnsupported, reason)}
	}
	switch mediaType {
	case eatContentType:
		if expectation.Policy.Evidence.DeviceMode == "caliptra" && !e.EnableCaliptraCompatibility {
			reason := "Caliptra compatibility is disabled"
			return nil, ComponentResult{Status: OutcomeUnsupported, Reason: reason, Dimensions: unresolvedDimensions(OutcomeUnsupported, reason)}
		}
		var claims *DeviceClaims
		var err error
		switch expectation.Policy.Evidence.DeviceMode {
		case "strict":
			claims, err = VerifyStrictDeviceEAT(decoded.DeviceEAT, nonce, expectation, currentTime, e.Limits)
		case "caliptra":
			claims, err = VerifyCaliptraDeviceEAT(decoded.DeviceEAT, nonce, expectation, e.Limits)
		default:
			err = errors.New("unsupported Device EAT policy mode")
		}
		if err != nil {
			dimensions := unresolvedDimensions(OutcomeIndeterminate, "Device EAT authentication did not complete")
			dimensions.EvidenceProtection = DimensionResult{Status: OutcomeFail, Reason: err.Error()}
			return nil, ComponentResult{Status: OutcomeFail, Reason: err.Error(), Dimensions: dimensions}
		}
		identityDER, err := x509.MarshalPKIXPublicKey(claims.SigningKey)
		if err != nil {
			dimensions := unresolvedDimensions(OutcomeIndeterminate, "Device EAT identity serialization failed")
			dimensions.Identity = DimensionResult{Status: OutcomeFail, Reason: err.Error()}
			return nil, ComponentResult{Status: OutcomeFail, Reason: err.Error(), Dimensions: dimensions}
		}
		identityDigest := sha256.Sum256(identityDER)
		return &authenticatedComponent{
			Identity: hex.EncodeToString(identityDigest[:]), Measurements: claims.EvidenceTriples,
			Dimensions: ComponentDimensions{
				EvidenceProtection: passDimension("Device EAT signature passed"),
				Freshness:          passDimension("Device EAT nonce matches the challenge"),
				Identity:           passDimension("Device EAT signing key is authorized"),
				Composition:        passDimension("component label is present in authenticated topology"),
				Measurements:       DimensionResult{Status: OutcomeIndeterminate, Reason: "measurements not yet appraised"},
				Policy:             passDimension("Device EAT mode selected by signed member policy: " + expectation.Policy.Evidence.DeviceMode),
			},
		}, ComponentResult{}
	case spdmEvidenceMediaType:
		if !e.EnableNativeSPDM {
			reason := "native SPDM verification is disabled"
			return nil, ComponentResult{Status: OutcomeUnsupported, Reason: reason, Dimensions: unresolvedDimensions(OutcomeUnsupported, reason)}
		}
		if decoded.SPDM == nil {
			reason := "SPDM carriage did not contain SPDM Evidence"
			return nil, ComponentResult{Status: OutcomeFail, Reason: reason, Dimensions: unresolvedDimensions(OutcomeIndeterminate, reason)}
		}
		component, err := verifySPDMComponent(*decoded.SPDM, nonce, expectation, currentTime, e.AllowSPDM10ReversedECDSA)
		if err != nil {
			dimensions := unresolvedDimensions(OutcomeIndeterminate, "SPDM authentication did not complete")
			var typed *commonspdm.VerificationError
			if errors.As(err, &typed) && (typed.Kind == commonspdm.ErrorUnsupported || typed.Kind == commonspdm.ErrorPolicy) {
				dimensions.Policy = DimensionResult{Status: OutcomeUnsupported, Reason: err.Error()}
				return nil, ComponentResult{Status: OutcomeUnsupported, Reason: err.Error(), Dimensions: dimensions}
			}
			dimensions.EvidenceProtection = DimensionResult{Status: OutcomeFail, Reason: err.Error()}
			return nil, ComponentResult{Status: OutcomeFail, Reason: err.Error(), Dimensions: dimensions}
		}
		return component, ComponentResult{}
	default:
		reason := fmt.Sprintf("unsupported native Evidence media type %q", mediaType)
		return nil, ComponentResult{Status: OutcomeUnsupported, Reason: reason, Dimensions: unresolvedDimensions(OutcomeUnsupported, reason)}
	}
}

func firstNonPassReason(dimensions ComponentDimensions) string {
	for _, result := range []DimensionResult{
		dimensions.EvidenceProtection, dimensions.Freshness, dimensions.Identity,
		dimensions.Composition, dimensions.Measurements, dimensions.Policy,
	} {
		if result.Status != OutcomePass {
			return result.Reason
		}
	}
	return "component appraisal did not pass"
}

func decodeLeadEvidence(encoded [][]byte) ([]comid.ValueTriple, error) {
	var result []comid.ValueTriple
	for index, value := range encoded {
		var concise coev.ConciseEvidence
		if err := concise.FromCBOR(value); err != nil {
			return nil, fmt.Errorf("decode Lead Concise Evidence %d: %w", index, err)
		}
		if concise.EvTriples.EvidenceTriples == nil {
			return nil, fmt.Errorf("lead Concise Evidence %d has no evidence triples", index)
		}
		result = append(result, concise.EvTriples.EvidenceTriples.Values...)
	}
	return result, nil
}

func compareMembership(expected map[string]MemberExpectation, observed map[string]DetachedDigest) string {
	var missing, extra []string
	for label := range expected {
		if _, ok := observed[label]; !ok && expected[label].Policy.Required {
			missing = append(missing, label)
		}
	}
	for label := range observed {
		if _, ok := expected[label]; !ok {
			extra = append(extra, label)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) == 0 && len(extra) == 0 {
		return ""
	}
	return fmt.Sprintf("composition mismatch: missing=%v extra=%v", missing, extra)
}
