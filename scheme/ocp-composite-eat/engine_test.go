// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"crypto/x509"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/coev"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/ear"
	"github.com/veraison/services/scheme/ocp-composite-eat/internal/evidencecarriage"
	commonspdm "github.com/veraison/services/scheme/ocp-composite-eat/internal/spdm"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

func TestClassProviderRequiresExactCompatibilitySourceDigest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	demo, err := newClassDemo(now)
	require.NoError(t, err)
	var sourceID string
	var source ComponentClassSource
	for sourceID, source = range demo.Input.Components {
		break
	}
	digest := sha256.Sum256(source.SignedCoRIM)
	demo.Input.Compatibility = platformcorim.CompatibilityPolicy{EvidenceCarriageBySource: map[string]platformcorim.CarriageAuthorization{
		sourceID: {SourceSHA256: hex.EncodeToString(digest[:]), Carriage: platformcorim.CarriageDirectMap},
	}}
	_, err = NewClassProvider(demo.Input, demo.SourceRoots, now)
	require.NoError(t, err)

	authorization := demo.Input.Compatibility.EvidenceCarriageBySource[sourceID]
	authorization.SourceSHA256 = strings.Repeat("0", sha256.Size*2)
	demo.Input.Compatibility.EvidenceCarriageBySource[sourceID] = authorization
	_, err = NewClassProvider(demo.Input, demo.SourceRoots, now)
	require.ErrorContains(t, err, "source digest mismatch")
}

func TestClassProviderSharesEndorsementsAcrossServers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	demo, err := newClassDemo(now)
	require.NoError(t, err)
	provider, err := NewClassProvider(demo.Input, demo.SourceRoots, now)
	require.NoError(t, err)
	demo.Input.Platform.Revision = "mutated-after-construction"
	demo.Input.Enrollments[0].Revision = "mutated-after-construction"
	engine := Engine{EndorsementProvider: provider, EvidenceRoots: demo.EvidenceRoots, EnableNativeSPDM: true, Limits: DefaultLimits(), Now: func() time.Time { return now }}
	reports := make([]*Report, 0, 2)
	for _, name := range []string{"server-0-good", "server-1-good"} {
		report, err := engine.Verify(demo.Bundles[name], demo.Nonce)
		require.NoError(t, err)
		require.Equal(t, OutcomePass, report.Status, report.Reason)
		reports = append(reports, report)
	}
	require.Equal(t, reports[0].CoRIMID, reports[1].CoRIMID)
	require.Equal(t, reports[0].SourceDigests, reports[1].SourceDigests)
	require.NotEqual(t, reports[0].EnrollmentID, reports[1].EnrollmentID)
	require.NotEqual(t, reports[0].SnapshotDigest, reports[1].SnapshotDigest)
	require.Len(t, reports[0].Components, 1)
	require.Len(t, reports[1].Components, 2)
	for _, name := range []string{"server-0-cross-server", "server-1-missing-required"} {
		report, err := engine.Verify(demo.Bundles[name], demo.Nonce)
		require.NoError(t, err)
		require.Equal(t, OutcomeFail, report.Status, name)
		if name == "server-0-cross-server" {
			require.Equal(t, OutcomePass, report.Components["env.controller.0"].Dimensions.EvidenceProtection.Status)
			require.Equal(t, OutcomeFail, report.Components["env.controller.0"].Dimensions.Identity.Status)
		} else {
			require.Equal(t, OutcomeFail, report.Components["env.controller.1"].Dimensions.Composition.Status)
		}
		claims, err := reportToMap(report)
		require.NoError(t, err)
		result, err := NewHandler().AppraiseClaims(claims, nil)
		require.NoError(t, err)
		require.NotEqual(t, ear.TrustTierAffirming, *result.Submods[SchemeName].Status)
	}
	t.Run("concurrent", func(t *testing.T) {
		for range 8 {
			t.Run("server", func(t *testing.T) {
				t.Parallel()
				for _, name := range []string{"server-0-good", "server-1-good"} {
					report, err := engine.Verify(demo.Bundles[name], demo.Nonce)
					require.NoError(t, err)
					require.Equal(t, OutcomePass, report.Status)
				}
			})
		}
	})
	enrollment := demo.Input.Enrollments[0]
	ueid, err := hex.DecodeString(enrollment.Lead.UEID)
	require.NoError(t, err)
	key, err := enrolledPublicKey(enrollment.Lead.PublicKeyPEM)
	require.NoError(t, err)
	request := EndorsementRequest{Profile: CompositeEATProfile, LeadUEID: ueid, LeadPublicKey: key, VerificationTime: now, ObservedLabels: []string{"env.arbitrary.observed"}}
	resolved, err := provider.Resolve(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "single", resolved.Variant)
	require.Len(t, resolved.Members, 1)
	resolved.LeadReferenceValues[0].Measurements.Values[0].Val.RawValue = nil
	resolved.SourceDigests["platform"] = "mutated"
	again, err := provider.Resolve(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, again.LeadReferenceValues[0].Measurements.Values[0].Val.RawValue)
	require.NotEqual(t, "mutated", again.SourceDigests["platform"])
	request.VerificationTime = now.Add(25 * time.Hour)
	_, err = provider.Resolve(context.Background(), request)
	require.Error(t, err)
	request.VerificationTime = now.Add(-2 * time.Hour)
	_, err = provider.Resolve(context.Background(), request)
	require.Error(t, err)
	signed, err := corim.UnmarshalAndValidateSignedCorimFromCBOR(demo.Input.SignedPlatform)
	require.NoError(t, err)
	comids, err := collectCoMIDs(&signed.UnsignedCorim)
	require.NoError(t, err)
	for _, item := range comids {
		require.Nil(t, item.Triples.AttestVerifKeys)
		for _, membership := range *item.Triples.DomainMemberships {
			require.Nil(t, membership.DomainID.Instance)
			for _, member := range membership.Members {
				require.Nil(t, member.Instance)
			}
		}
	}
	for _, source := range demo.Input.Components {
		signed, err := corim.UnmarshalAndValidateSignedCorimFromCBOR(source.SignedCoRIM)
		require.NoError(t, err)
		comids, err := collectCoMIDs(&signed.UnsignedCorim)
		require.NoError(t, err)
		for _, item := range comids {
			require.Nil(t, item.Triples.AttestVerifKeys)
			for _, reference := range item.Triples.ReferenceValues.Values {
				require.Nil(t, reference.Environment.Instance)
			}
		}
	}
}

func TestClassProviderRejectsUnendorsedEnrollmentAndSources(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	demo, err := newClassDemo(now)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*ClassProviderInput){
		"sku":            func(input *ClassProviderInput) { input.Enrollments[0].SKU = "unapproved" },
		"revision":       func(input *ClassProviderInput) { input.Enrollments[0].PlatformRevision = "older" },
		"variant":        func(input *ClassProviderInput) { input.Enrollments[1].Variant = "single" },
		"missing-member": func(input *ClassProviderInput) { delete(input.Enrollments[1].Members, "env.controller.1") },
		"wrong-class": func(input *ClassProviderInput) {
			member := input.Enrollments[0].Members["env.controller.0"]
			member.Class = "unapproved"
			input.Enrollments[0].Members["env.controller.0"] = member
		},
		"duplicate-key": func(input *ClassProviderInput) {
			input.Enrollments[1].Members["env.controller.0"] = input.Enrollments[0].Members["env.controller.0"]
		},
		"scope":       func(input *ClassProviderInput) { input.SignerScopes["platform"] = "unapproved" },
		"class-drift": func(input *ClassProviderInput) { input.Platform.Revision = "tampered" },
		"component-drift": func(input *ClassProviderInput) {
			for id, source := range input.Components {
				source.Manifest.References[0].Value = "00"
				input.Components[id] = source
			}
		},
		"reference-selection": func(input *ClassProviderInput) {
			variant := input.Platform.Variants["single"]
			variant.Members[0].ReferenceSetID = "unapproved"
			input.Platform.Variants["single"] = variant
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(demo.Input)
			require.NoError(t, err)
			var input ClassProviderInput
			require.NoError(t, json.Unmarshal(encoded, &input))
			mutate(&input)
			_, err = NewClassProvider(input, demo.SourceRoots, now)
			require.Error(t, err)
		})
	}
}

func TestEngineVerifiesCompleteBundle(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	nonce := testNonce()
	bundle := buildCompositeBundle(t, fixture, snapshot, nonce, fixture.deviceKey)
	engine := Engine{Snapshot: snapshot, EvidenceRoots: fixture.leadRoots, EnableCaliptraCompatibility: true, Limits: DefaultLimits(), Now: func() time.Time { return fixture.now }}

	report, err := engine.Verify(bundle, nonce)
	require.NoError(t, err)
	require.Equal(t, OutcomePass, report.Status)
	require.Equal(t, OutcomePass, report.Components["env.device.0"].Status)
}

func TestEnginePreservesChildFailure(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	nonce := testNonce()
	bundle := buildCompositeBundle(t, fixture, snapshot, nonce, wrongKey)
	engine := Engine{Snapshot: snapshot, EvidenceRoots: fixture.leadRoots, EnableCaliptraCompatibility: true, Limits: DefaultLimits(), Now: func() time.Time { return fixture.now }}

	report, err := engine.Verify(bundle, nonce)
	require.NoError(t, err)
	require.Equal(t, OutcomeFail, report.Status)
	require.Contains(t, report.Components["env.device.0"].Reason, "authorized identity key")
}

func TestEngineDoesNotEnableCaliptraCompatibilityByDefault(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	nonce := testNonce()
	bundle := buildCompositeBundle(t, fixture, snapshot, nonce, fixture.deviceKey)
	engine := Engine{Snapshot: snapshot, EvidenceRoots: fixture.leadRoots, Limits: DefaultLimits(), Now: func() time.Time { return fixture.now }}

	report, err := engine.Verify(bundle, nonce)
	require.NoError(t, err)
	require.Equal(t, OutcomeFail, report.Status)
	require.Equal(t, OutcomeUnsupported, report.Components["env.device.0"].Status)
	require.Equal(t, "Caliptra compatibility is disabled", report.Components["env.device.0"].Reason)
	require.Equal(t, OutcomeUnsupported, report.Components["env.device.0"].Dimensions.Policy.Status)
}

func buildCompositeBundle(
	t *testing.T,
	fixture snapshotFixture,
	snapshot *Snapshot,
	nonce []byte,
	deviceKey *ecdsa.PrivateKey,
) []byte {
	t.Helper()
	require.Len(t, snapshot.Members, 1)
	var expectation MemberExpectation
	for _, member := range snapshot.Members {
		expectation = member
	}
	deviceToken := buildCaliptraDeviceToken(t, deviceKey, nonce, expectation)
	claimsSet := mustEncode(t, map[int64]any{
		cmwClaim: []any{eatContentType, deviceToken, uint64(4)},
	})
	return buildCompositeBundleWithClaims(t, fixture, snapshot, nonce, claimsSet)
}

func buildCompositeBundleWithClaims(
	t *testing.T,
	fixture snapshotFixture,
	snapshot *Snapshot,
	nonce, claimsSet []byte,
) []byte {
	t.Helper()
	require.Len(t, snapshot.Members, 1)
	var label string
	for name := range snapshot.Members {
		label = name
	}
	profile := snapshot.CompositeEATProfile
	if profile == "" {
		profile = CompositeEATProfile
	}
	claimsSetDigest := sha512.Sum384(claimsSet)

	leadConcise := coev.NewConciseEvidence()
	leadTriples := coev.NewEvTriples()
	for index := range snapshot.LeadReferenceValues {
		triple := snapshot.LeadReferenceValues[index]
		leadTriples.AddEvidenceTriple(&triple)
	}
	require.NoError(t, leadConcise.AddTriples(leadTriples))
	leadEvidence, err := leadConcise.ToCBOR()
	require.NoError(t, err)

	payload := mustEncode(t, map[int64]any{
		claimNonce:        nonce,
		claimUEID:         fixture.leadUEID,
		claimProfile:      profile,
		claimSubmods:      map[string]any{label: []any{int64(sha384COSEAlgorithm), claimsSetDigest[:]}},
		claimMeasurements: []any{[]any{uint64(conciseEvidenceFormat), leadEvidence}},
	})
	thumbprint := sha512.Sum384(fixture.leadCertificate.Raw)
	protected := mustEncode(t, map[int64]any{
		headerAlgorithm: int64(es384COSEAlgorithm), headerContentType: eatContentType,
		headerX5Thumbprint: []any{int64(sha384COSEAlgorithm), thumbprint[:]},
	})
	sigStructure := mustEncode(t, []any{"Signature1", protected, []byte{}, payload})
	digest := sha512.Sum384(sigStructure)
	r, s, err := ecdsa.Sign(rand.Reader, fixture.leadKey, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	mainToken := mustEncode(t, cbor.Tag{Number: cwtTag, Content: cbor.Tag{
		Number: coseSign1Tag, Content: []any{
			protected, map[int64]any{headerX5Chain: fixture.leadCertificate.Raw}, payload, signature,
		},
	}})
	return mustEncode(t, cbor.Tag{Number: detachedEATBundleTag, Content: []any{
		mainToken, map[string]any{label: claimsSet},
	}})
}

func TestEngineDirectMapRequiresSelectedCompatibility(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	nonce := testNonce()
	member := snapshot.Members["env.device.0"]
	deviceToken := buildCaliptraDeviceToken(t, fixture.deviceKey, nonce, member)
	claimsSet := mustEncode(t, map[string]any{"token_format": eatContentType, "device_token": deviceToken})
	bundle := buildCompositeBundleWithClaims(t, fixture, snapshot, nonce, claimsSet)
	engine := Engine{Snapshot: snapshot, EvidenceRoots: fixture.leadRoots, EnableCaliptraCompatibility: true, Limits: DefaultLimits(), Now: func() time.Time { return fixture.now }}

	report, err := engine.Verify(bundle, nonce)
	require.NoError(t, err)
	require.Equal(t, OutcomeFail, report.Status)
	require.Equal(t, "cmw-encoding", report.ComponentCarriage[member.Label])

	member.Carriage = platformcorim.CarriageDirectMap
	member.Compatibility = true
	snapshot.Members[member.Label] = member
	report, err = engine.Verify(bundle, nonce)
	require.NoError(t, err)
	require.Equal(t, OutcomePass, report.Status, report.Reason)
	require.Equal(t, platformcorim.CarriageDirectMap, report.ComponentCarriage[member.Label])
	require.True(t, report.CompatibilityUsed[member.Label])
	claims, err := reportToMap(report)
	require.NoError(t, err)
	result, err := NewHandler().AppraiseClaims(claims, nil)
	require.NoError(t, err)
	annotations := *result.Submods[SchemeName].VeraisonAnnotatedEvidence
	require.Contains(t, annotations, "component-carriage")
	require.Contains(t, annotations, "carriage-compatibility-used")
}

func TestEngineExplicitContractAndLeadFlags(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	member := snapshot.Members["env.device.0"]
	member.Label = "env.controller.slota"
	snapshot.Members = map[string]MemberExpectation{member.Label: member}
	snapshot.Profile = manifest.ExplicitPlatformProfile
	snapshot.CompositeEATProfile = "tag:example.com,2026:strict-platform-v1"
	measured := comid.Environment{Class: comid.NewClassBytes([]byte("immutable-boot")).SetModel("boot")}
	measurement := comid.MustNewMeasurement("boot-register", comid.StringType).AddDigest(comid.Sha512, make([]byte, 64))
	measurement.Val.Flags = comid.NewFlagsMap()
	measurement.Val.Flags.SetTrue(comid.FlagIsImmutable)
	measurement.Val.Flags.SetFalse(comid.FlagIsDebug)
	snapshot.LeadReferenceValues = append(snapshot.LeadReferenceValues, comid.ValueTriple{Environment: measured, Measurements: *comid.NewMeasurements().Add(measurement)})
	bundle := buildCompositeBundle(t, fixture, snapshot, testNonce(), fixture.deviceKey)
	engine := Engine{Snapshot: snapshot, EvidenceRoots: fixture.leadRoots, CompositeEATProfile: snapshot.CompositeEATProfile, EnableCaliptraCompatibility: true, Limits: DefaultLimits(), Now: func() time.Time { return fixture.now }}
	report, err := engine.Verify(bundle, testNonce())
	require.NoError(t, err)
	require.Equal(t, OutcomePass, report.Status)
	engine.CompositeEATProfile = ""
	_, err = engine.Verify(bundle, testNonce())
	require.ErrorContains(t, err, "is not enabled")
	engine.CompositeEATProfile = snapshot.CompositeEATProfile
	snapshot.LeadReferenceValues[1].Measurements.Values[0].Val.Flags.SetTrue(comid.FlagIsDebug)
	report, err = engine.Verify(bundle, testNonce())
	require.NoError(t, err)
	require.Equal(t, OutcomeFail, report.Lead.Dimensions.Measurements.Status)
	claims, err := reportToMap(report)
	require.NoError(t, err)
	result, err := NewHandler().AppraiseClaims(claims, nil)
	require.NoError(t, err)
	require.NotEqual(t, ear.TrustTierAffirming, *result.Submods[SchemeName].Status)
}

func TestCrossFormatKeyReuseAndStrictNoFallback(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	original := snapshot.Members["env.device.0"]
	nonce := testNonce()
	engine := Engine{Snapshot: snapshot, EvidenceRoots: fixture.leadRoots, EnableNativeSPDM: true, EnableCaliptraCompatibility: true, Limits: DefaultLimits(), Now: func() time.Time { return fixture.now }}
	legacy := buildCaliptraDeviceToken(t, fixture.deviceKey, nonce, original)
	strictExpectation := original
	strictExpectation.Policy.Evidence.DeviceMode = "strict"
	component, result := engine.verifyComponent(&evidencecarriage.DecodedEvidence{MediaType: eatContentType, DeviceEAT: legacy}, nonce, strictExpectation, fixture.now)
	require.Nil(t, component)
	require.Equal(t, OutcomeFail, result.Status)
	root, err := demoMakeCertificate(nil, nil, true, "Test Root", fixture.now)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: root.Cert.SerialNumber, NotBefore: root.Cert.NotBefore, NotAfter: root.Cert.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, root.Cert, &fixture.deviceKey.PublicKey, root.Key)
	require.NoError(t, err)
	leaf := &demoKeyPair{Key: fixture.deviceKey, DER: der}
	strictToken, err := demoStrictDeviceEAT(leaf, nonce, original.ReferenceValues)
	require.NoError(t, err)
	component, _ = engine.verifyComponent(&evidencecarriage.DecodedEvidence{MediaType: eatContentType, DeviceEAT: strictToken}, nonce, strictExpectation, fixture.now)
	require.NotNil(t, component)
	_, err = VerifyCaliptraDeviceEAT(strictToken, nonce, original, DefaultLimits())
	require.Error(t, err)
	member := original
	member.Label = "env.spdm.0"
	member.Environment.Class = comid.NewClassBytes([]byte("demo-spdm")).SetModel("spdm").SetIndex(0)
	member.Policy.Evidence = manifest.EvidencePolicy{MediaType: spdmEvidenceMediaType, SPDMVersions: []uint16{0x12}, BaseHashes: []string{"sha-384"}, BaseAsym: []string{"ecdsa-p384"}}
	measurement := comid.MustNewMeasurement(uint(1), comid.UintType)
	measurement.SetRawValueBytes([]byte("firmware"), nil)
	member.ReferenceValues = []comid.ValueTriple{{Environment: member.Environment, Measurements: *comid.NewMeasurements().Add(measurement)}}
	snapshot.Members[member.Label] = member
	spdmClaims, err := demoSPDMClaimsSet(root, leaf, nonce, []byte("firmware"), false, spdmEvidenceMediaType)
	require.NoError(t, err)
	claimsSets := map[string][]byte{"env.device.0": mustEncode(t, map[int64]any{cmwClaim: []any{eatContentType, legacy, uint64(4)}}), member.Label: spdmClaims}
	submods := map[string]any{}
	for label, value := range claimsSets {
		digest := sha512.Sum384(value)
		submods[label] = []any{int64(sha384COSEAlgorithm), digest[:]}
	}
	lead := &demoKeyPair{Key: fixture.leadKey, DER: fixture.leadCertificate.Raw, Cert: fixture.leadCertificate}
	encoded, err := demoBundleFromClaimsSets(lead, lead, fixture.leadUEID, nonce, snapshot.LeadReferenceValues, claimsSets, submods)
	require.NoError(t, err)
	report, err := engine.Verify(encoded, nonce)
	require.NoError(t, err)
	require.Equal(t, OutcomeFail, report.Status)
	require.Equal(t, OutcomeFail, report.Components[member.Label].Dimensions.Composition.Status)
	claims, err := reportToMap(report)
	require.NoError(t, err)
	earResult, err := NewHandler().AppraiseClaims(claims, nil)
	require.NoError(t, err)
	require.NotEqual(t, ear.TrustTierAffirming, *earResult.Submods[SchemeName].Status)
}

func TestEngineVerifiesAuthorizedDirectMapSPDM(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	nonce := testNonce()
	original := snapshot.Members["env.device.0"]
	root, err := demoMakeCertificate(nil, nil, true, "Direct Map SPDM Root", fixture.now)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: root.Cert.SerialNumber, NotBefore: root.Cert.NotBefore, NotAfter: root.Cert.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, root.Cert, &fixture.deviceKey.PublicKey, root.Key)
	require.NoError(t, err)
	leaf := &demoKeyPair{Key: fixture.deviceKey, DER: der}

	member := original
	member.Label = "env.spdm.0"
	member.Carriage = platformcorim.CarriageDirectMap
	member.Compatibility = true
	member.Environment.Class = comid.NewClassBytes([]byte("direct-map-spdm")).SetModel("spdm").SetIndex(0)
	member.Policy.Evidence = manifest.EvidencePolicy{MediaType: spdmEvidenceMediaType, SPDMVersions: []uint16{0x12}, BaseHashes: []string{"sha-384"}, BaseAsym: []string{"ecdsa-p384"}}
	measurement := comid.MustNewMeasurement(uint(1), comid.UintType)
	measurement.SetRawValueBytes([]byte("firmware"), nil)
	member.ReferenceValues = []comid.ValueTriple{{Environment: member.Environment, Measurements: *comid.NewMeasurements().Add(measurement)}}
	snapshot.Members = map[string]MemberExpectation{member.Label: member}

	cmwClaims, err := demoSPDMClaimsSet(root, leaf, nonce, []byte("firmware"), false, spdmEvidenceMediaType)
	require.NoError(t, err)
	var claims map[int64][]any
	require.NoError(t, cbor.Unmarshal(cmwClaims, &claims))
	native, ok := claims[cmwClaim][1].([]byte)
	require.True(t, ok)
	var fields [][]byte
	require.NoError(t, cbor.Unmarshal(native, &fields))
	require.Len(t, fields, 2)
	directMap := mustEncode(t, map[string]any{"signed_measurements": fields[0], "cert_chain": fields[1]})
	bundle := buildCompositeBundleWithClaims(t, fixture, snapshot, nonce, directMap)
	engine := Engine{Snapshot: snapshot, EvidenceRoots: fixture.leadRoots, EnableNativeSPDM: true, Limits: DefaultLimits(), Now: func() time.Time { return fixture.now }}
	report, err := engine.Verify(bundle, nonce)
	require.NoError(t, err)
	require.Equal(t, OutcomePass, report.Status, report.Reason)
	require.Equal(t, platformcorim.CarriageDirectMap, report.ComponentCarriage[member.Label])
	require.True(t, report.CompatibilityUsed[member.Label])
}

func TestSPDMVersionSemanticFailurePreservesAuthenticatedDimensions(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	nonce := testNonce()
	expectation := snapshot.Members["env.device.0"]
	expectation.Policy.Evidence = manifest.EvidencePolicy{MediaType: spdmEvidenceMediaType, SPDMVersions: []uint16{0x12}, BaseHashes: []string{"sha-384"}, BaseAsym: []string{"ecdsa-p384"}}
	root, err := demoMakeCertificate(nil, nil, true, "Semantic Test Root", fixture.now)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: root.Cert.SerialNumber, NotBefore: root.Cert.NotBefore, NotAfter: root.Cert.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, root.Cert, &fixture.deviceKey.PublicKey, root.Key)
	require.NoError(t, err)
	leaf := &demoKeyPair{Key: fixture.deviceKey, DER: der}
	claimsSet, err := demoSPDMClaimsSetWithType(root, leaf, nonce, []byte("informational"), false, spdmEvidenceMediaType, 0x89)
	require.NoError(t, err)
	decoded, err := DecodeNativeEvidence(claimsSet, "cmw-encoding", spdmEvidenceMediaType, DefaultLimits())
	require.NoError(t, err)
	engine := Engine{EnableNativeSPDM: true}
	component, result := engine.verifyComponent(decoded, nonce, expectation, fixture.now)
	require.NotNil(t, component)
	require.Empty(t, result.Reason)
	require.Equal(t, OutcomePass, component.Dimensions.EvidenceProtection.Status)
	require.Equal(t, OutcomePass, component.Dimensions.Freshness.Status)
	require.Equal(t, OutcomePass, component.Dimensions.Identity.Status)
	require.Equal(t, OutcomeUnsupported, component.Dimensions.Policy.Status)
	require.Contains(t, component.Dimensions.Policy.Reason, "reserved in SPDM 1.2")
	require.Equal(t, OutcomeUnsupported, component.Dimensions.Measurements.Status)
	require.Contains(t, component.Dimensions.Measurements.Reason, "reserved in SPDM 1.2")

	expectation.Policy.Evidence.SPDMMeasurementTypePolicy = manifest.SPDMMeasurementTypePolicyKnownTypes
	component, result = engine.verifyComponent(decoded, nonce, expectation, fixture.now)
	require.Empty(t, result.Reason)
	require.NotNil(t, component)
	require.Equal(t, OutcomePass, component.Dimensions.Policy.Status)
	require.Contains(t, component.Dimensions.Policy.Reason, "recognized measurement types across versions")
	require.Equal(t, OutcomeIndeterminate, component.Dimensions.Measurements.Status)
	require.Len(t, component.Measurements, 1)
	require.Equal(t, "informational", *component.Measurements[0].Measurements.Values[0].Val.Name)
}

func TestSPDMMeasurementsToCoMIDPreservesTypeNames(t *testing.T) {
	expectedNames := []string{
		"immutable-rom", "mutable-firmware", "hardware-config", "firmware-config",
		"freeform-manifest", "device-mode", "mutable-firmware-version",
		"mutable-firmware-svn", "hash-extended-measurement", "informational",
		"structured-measurement-manifest",
	}
	blocks := make([]commonspdm.MeasurementBlock, 0, commonspdm.MeasurementTypeStructuredManifest+1)
	for valueType := uint8(0); valueType <= commonspdm.MeasurementTypeStructuredManifest; valueType++ {
		blocks = append(blocks, commonspdm.MeasurementBlock{
			Index: byte(valueType + 1), MeasurementSpecification: 1, ValueType: valueType,
			RawBitStream: true, Value: []byte{valueType},
		})
	}
	triples, err := spdmMeasurementsToCoMID(comid.Environment{}, &commonspdm.Result{Version: commonspdm.Version13, Measurements: blocks})
	require.NoError(t, err)
	require.Len(t, triples, 1)
	require.Len(t, triples[0].Measurements.Values, len(blocks))
	for index, measurement := range triples[0].Measurements.Values {
		require.NotNil(t, measurement.Val.Name)
		require.Equal(t, expectedNames[index], *measurement.Val.Name)
	}
}
