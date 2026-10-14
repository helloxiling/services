// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"time"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

const PlatformCoRIMProfile = "tag:example.com,2026:platform-composite-eat-model-index#0.5.0"

var memberModelPattern = regexp.MustCompile(`^[a-z0-9]+$`)

type MemberExpectation struct {
	Label           string
	Environment     comid.Environment
	Identity        []byte
	IdentityKeys    []crypto.PublicKey
	ReferenceValues []comid.ValueTriple
	Policy          manifest.MemberPolicy
	SourceID        string
	Carriage        string
	Compatibility   bool
}

type Snapshot struct {
	CoRIMID             string
	Digest              string
	Profile             string
	CompositeEATProfile string
	Platform            comid.Environment
	LeadKeys            []crypto.PublicKey
	LeadReferenceValues []comid.ValueTriple
	Members             map[string]MemberExpectation
	ValidUntil          time.Time
	SourceDigests       map[string]string
	EnrollmentID        string
	EnrollmentRevision  string
	Variant             string
}

func LoadSnapshotFile(path string, roots *x509.CertPool, currentTime time.Time) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Platform CoRIM: %w", err)
	}
	return LoadSnapshot(data, roots, currentTime)
}

func LoadSnapshot(data []byte, roots *x509.CertPool, currentTime time.Time) (*Snapshot, error) {
	if roots == nil {
		return nil, errors.New("platform CoRIM roots are not configured")
	}
	if currentTime.IsZero() {
		currentTime = time.Now()
	}
	if len(data) == 0 {
		return nil, errors.New("platform CoRIM is empty")
	}

	signed, err := corim.UnmarshalAndValidateSignedCorimFromCBOR(data)
	if err != nil {
		return nil, fmt.Errorf("decode signed Platform CoRIM: %w", err)
	}
	if signed.SigningCert == nil {
		return nil, errors.New("platform CoRIM has no signing certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range signed.IntermediateCerts {
		intermediates.AddCert(cert)
	}
	if _, err := signed.SigningCert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: currentTime,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("validate Platform CoRIM signer: %w", err)
	}
	if err := signed.Verify(signed.SigningCert.PublicKey); err != nil {
		return nil, fmt.Errorf("verify Platform CoRIM signature: %w", err)
	}
	if err := checkValidity("Platform CoRIM signer metadata", signed.Meta.Validity, currentTime); err != nil {
		return nil, err
	}
	if err := checkValidity("Platform CoRIM", signed.UnsignedCorim.RimValidity, currentTime); err != nil {
		return nil, err
	}
	profile := profileString(signed.UnsignedCorim.Profile)
	if profile != PlatformCoRIMProfile && profile != manifest.ExplicitPlatformProfile {
		return nil, fmt.Errorf("unexpected Platform CoRIM profile %q", profileString(signed.UnsignedCorim.Profile))
	}

	comids, err := collectCoMIDs(&signed.UnsignedCorim)
	if err != nil {
		return nil, err
	}
	contract, err := snapshotContract(comids, profile)
	if err != nil {
		return nil, err
	}
	platform, members, err := collectMembership(comids, contract)
	if err != nil {
		return nil, err
	}

	leadKeys := collectKeys(comids, platform, true)
	if len(leadKeys) == 0 {
		return nil, errors.New("platform CoRIM has no authorized Lead Attester key")
	}
	leadReferenceValues := collectReferenceValues(comids, platform)
	evidenceProfile := CompositeEATProfile
	if contract != nil {
		evidenceProfile = contract.CompositeEATProfile
		leadReferenceValues = nil
		for index, environment := range contract.LeadEnvironments {
			for _, previous := range contract.LeadEnvironments[:index] {
				if reflect.DeepEqual(previous, environment) {
					return nil, errors.New("duplicate Lead measurement environment")
				}
			}
			references := collectReferenceValues(comids, environment)
			if len(references) == 0 {
				return nil, errors.New("missing references for signed Lead measurement environment")
			}
			leadReferenceValues = append(leadReferenceValues, references...)
		}
	}
	if len(leadReferenceValues) == 0 {
		return nil, errors.New("platform CoRIM has no Lead Attester reference values")
	}

	for label, member := range members {
		member.IdentityKeys = collectKeys(comids, member.Environment, true)
		if len(member.IdentityKeys) == 0 {
			return nil, fmt.Errorf("platform CoRIM member %q has no attestation verification key", label)
		}
		foundPolicy := false
		for _, item := range comids {
			policy, ok := item.GetExtensions().(*manifest.PolicyExtension)
			if !ok || (contract == nil && policy.Binding != "demo-model-index-v1") || (contract != nil && policy != contract) {
				continue
			}
			if entry, exists := policy.Members[label]; exists {
				if foundPolicy {
					return nil, fmt.Errorf("ambiguous policy for %q", label)
				}
				if err := entry.Evidence.Validate(); err != nil {
					return nil, err
				}
				if entry.ReferenceSet == "" {
					return nil, errors.New("reference set ID is required")
				}
				member.Policy = entry
				foundPolicy = true
			}
		}
		if !foundPolicy {
			return nil, fmt.Errorf("missing signed policy for %q", label)
		}
		member.ReferenceValues = collectReferenceValues(comids, member.Environment)
		if len(member.ReferenceValues) == 0 {
			return nil, fmt.Errorf("platform CoRIM member %q has no reference values", label)
		}
		members[label] = member
	}

	digest := sha256.Sum256(data)
	validUntil := minimumNotAfter(signed.Meta.Validity, signed.UnsignedCorim.RimValidity)
	if signed.SigningCert.NotAfter.Before(validUntil) {
		validUntil = signed.SigningCert.NotAfter
	}
	return &Snapshot{
		CoRIMID:             signed.UnsignedCorim.GetID(),
		Digest:              hex.EncodeToString(digest[:]),
		Profile:             profile,
		CompositeEATProfile: evidenceProfile,
		Platform:            platform,
		LeadKeys:            leadKeys,
		LeadReferenceValues: leadReferenceValues,
		Members:             members,
		ValidUntil:          validUntil,
	}, nil
}

func (s *Snapshot) AuthorizeLead(claims *LeadClaims) error {
	if s.Platform.Instance == nil || !bytes.Equal(s.Platform.Instance.Bytes(), claims.UEID) {
		return errors.New("lead Attester UEID is not authorized for the platform domain")
	}
	for _, key := range s.LeadKeys {
		if publicKeysEqual(key, claims.Leaf.PublicKey) {
			return nil
		}
	}
	return errors.New("lead Attester signing key is not authorized by the Platform CoRIM")
}

func collectCoMIDs(unsigned *corim.UnsignedCorim) ([]*comid.Comid, error) {
	var result []*comid.Comid
	for _, tag := range unsigned.Tags {
		if tag.Number != corim.ComidTag {
			return nil, errors.New("snapshot supports only CoMID tags")
		}
		item := comid.NewComid()
		if err := manifest.RegisterPolicy(item, &manifest.PolicyExtension{}); err != nil {
			return nil, err
		}
		if err := item.FromCBOR(tag.Content); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if len(result) == 0 {
		return nil, errors.New("platform CoRIM contains no CoMID")
	}
	return result, nil
}

func snapshotContract(comids []*comid.Comid, profile string) (*manifest.PolicyExtension, error) {
	var contract *manifest.PolicyExtension
	for _, item := range comids {
		policy, ok := item.GetExtensions().(*manifest.PolicyExtension)
		if !ok {
			continue
		}
		if profile == PlatformCoRIMProfile {
			if policy.CompositeEATProfile != "" || len(policy.LeadEnvironments) != 0 || policy.Binding == manifest.ExplicitBinding {
				return nil, errors.New("explicit contract fields are not allowed in the legacy profile")
			}
			for _, member := range policy.Members {
				if member.Environment != nil {
					return nil, errors.New("explicit member binding is not allowed in the legacy profile")
				}
			}
			continue
		}
		if policy.Binding != manifest.ExplicitBinding || contract != nil {
			return nil, errors.New("explicit snapshot requires one unambiguous signed contract")
		}
		contract = policy
	}
	if profile == manifest.ExplicitPlatformProfile {
		if contract == nil || len(contract.LeadEnvironments) == 0 || len(contract.Members) == 0 {
			return nil, errors.New("explicit snapshot contract is incomplete")
		}
		if err := manifest.ValidateProfileURI(contract.CompositeEATProfile); err != nil {
			return nil, err
		}
	}
	return contract, nil
}

func collectMembership(comids []*comid.Comid, contracts ...*manifest.PolicyExtension) (comid.Environment, map[string]MemberExpectation, error) {
	var contract *manifest.PolicyExtension
	if len(contracts) > 0 {
		contract = contracts[0]
	}
	var memberships []comid.DomainMembershipTriple
	for _, item := range comids {
		if item.Triples.DomainMemberships != nil {
			memberships = append(memberships, *item.Triples.DomainMemberships...)
		}
	}
	if len(memberships) != 1 {
		return comid.Environment{}, nil, fmt.Errorf("platform CoRIM must contain exactly one membership triple, got %d", len(memberships))
	}

	members := make(map[string]MemberExpectation, len(memberships[0].Members))
	for _, environment := range memberships[0].Members {
		label, err := labelFromEnvironment(environment)
		if contract != nil {
			label, err = "", nil
			for candidate, policy := range contract.Members {
				if policy.Environment != nil && reflect.DeepEqual(*policy.Environment, environment) {
					if label != "" || !manifest.ValidExplicitLabel(candidate) {
						return comid.Environment{}, nil, errors.New("ambiguous or invalid explicit member binding")
					}
					label = candidate
				}
			}
			if label == "" {
				return comid.Environment{}, nil, errors.New("membership environment has no signed label binding")
			}
		}
		if err != nil {
			return comid.Environment{}, nil, err
		}
		if _, exists := members[label]; exists {
			return comid.Environment{}, nil, fmt.Errorf("duplicate Platform CoRIM member label %q", label)
		}
		if environment.Instance == nil && contract == nil {
			return comid.Environment{}, nil, fmt.Errorf("platform CoRIM member %q has no native identity", label)
		}
		member := MemberExpectation{Label: label, Environment: environment}
		if environment.Instance != nil {
			member.Identity = append([]byte(nil), environment.Instance.Bytes()...)
		}
		members[label] = member
	}
	if contract != nil && len(members) != len(contract.Members) {
		return comid.Environment{}, nil, errors.New("signed label bindings do not match domain membership")
	}
	if len(members) == 0 {
		return comid.Environment{}, nil, errors.New("platform CoRIM membership is empty")
	}
	return memberships[0].DomainID, members, nil
}

func labelFromEnvironment(environment comid.Environment) (string, error) {
	if environment.Class == nil || environment.Class.Model == nil || environment.Class.Index == nil {
		return "", errors.New("platform CoRIM member requires class model and index")
	}
	model := *environment.Class.Model
	if !memberModelPattern.MatchString(model) {
		return "", fmt.Errorf("platform CoRIM member model %q cannot form an env.* label", model)
	}
	label := fmt.Sprintf("env.%s.%d", model, *environment.Class.Index)
	if err := validateEnvironmentID(label); err != nil {
		return "", err
	}
	return label, nil
}

func collectKeys(comids []*comid.Comid, environment comid.Environment, lead bool) []crypto.PublicKey {
	var result []crypto.PublicKey
	for _, item := range comids {
		var triples *comid.KeyTriples
		if lead {
			triples = item.Triples.AttestVerifKeys
		} else {
			triples = item.Triples.DevIdentityKeys
		}
		if triples == nil {
			continue
		}
		for _, triple := range *triples {
			if !reflect.DeepEqual(triple.Environment, environment) {
				continue
			}
			for _, encodedKey := range triple.VerifKeys {
				key, err := encodedKey.PublicKey()
				if err == nil {
					result = append(result, key)
				}
			}
		}
	}
	return result
}

func collectReferenceValues(comids []*comid.Comid, environment comid.Environment) []comid.ValueTriple {
	var result []comid.ValueTriple
	for _, item := range comids {
		if item.Triples.ReferenceValues == nil {
			continue
		}
		for _, triple := range item.Triples.ReferenceValues.Values {
			if reflect.DeepEqual(triple.Environment, environment) {
				result = append(result, triple)
			}
		}
	}
	sort.SliceStable(result, func(left, right int) bool {
		return firstMeasurementKey(result[left]) < firstMeasurementKey(result[right])
	})
	return result
}

func firstMeasurementKey(triple comid.ValueTriple) string {
	if len(triple.Measurements.Values) == 0 {
		return ""
	}
	return measurementKey(triple.Measurements.Values[0])
}

func measurementKey(measurement comid.Measurement) string {
	if measurement.Key == nil {
		return ""
	}
	return measurement.Key.Value.String()
}

func checkValidity(name string, validity *corim.Validity, currentTime time.Time) error {
	if validity == nil {
		return fmt.Errorf("%s has no validity", name)
	}
	if validity.NotBefore != nil && currentTime.Before(*validity.NotBefore) {
		return fmt.Errorf("%s is not yet valid", name)
	}
	if currentTime.After(validity.NotAfter) {
		return fmt.Errorf("%s is expired", name)
	}
	return nil
}

func minimumNotAfter(validities ...*corim.Validity) time.Time {
	var result time.Time
	for _, validity := range validities {
		if validity != nil && (result.IsZero() || validity.NotAfter.Before(result)) {
			result = validity.NotAfter
		}
	}
	return result
}

func profileString(profile *corim.Profile) string {
	if profile == nil {
		return ""
	}
	return profile.String()
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}
