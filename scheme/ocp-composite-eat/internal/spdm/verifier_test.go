// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package spdm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExperimentalVerifierGeneratedVectors(t *testing.T) {
	tests := []struct {
		name     string
		version  Version
		hash     BaseHashAlgorithm
		asym     BaseAsymAlgorithm
		curve    elliptic.Curve
		vcaBound bool
	}{
		{name: "spdm-1.0-p384-sha384", version: Version10, hash: BaseHashSHA384, asym: BaseAsymECDSAP384, curve: elliptic.P384()},
		{name: "spdm-1.2-p256-sha256", version: Version12, hash: BaseHashSHA256, asym: BaseAsymECDSAP256, curve: elliptic.P256(), vcaBound: true},
		{name: "spdm-1.2-p384-sha384", version: Version12, hash: BaseHashSHA384, asym: BaseAsymECDSAP384, curve: elliptic.P384(), vcaBound: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSPDMFixture(t, test.version, test.hash, test.asym, test.curve, false)
			result, err := NewExperimentalVerifier().Verify(context.Background(), fixture.evidence, fixture.policy)
			require.NoError(t, err)
			require.Equal(t, test.version, result.Version)
			require.Equal(t, test.hash, result.BaseHash)
			require.Equal(t, test.asym, result.BaseAsym)
			require.Equal(t, test.vcaBound, result.VCAAuthenticated)
			require.Equal(t, OutcomePass, result.RootTrust)
			require.Equal(t, OutcomePass, result.IdentityAuthorization)
			require.Len(t, result.Measurements, 1)
			require.True(t, result.Measurements[0].RawBitStream)
		})
	}
}

func TestExperimentalVerifierRejectsWrongNonceAndSignature(t *testing.T) {
	fixture := newSPDMFixture(t, Version12, BaseHashSHA384, BaseAsymECDSAP384, elliptic.P384(), false)
	wrongNonce := fixture.policy
	wrongNonce.ExpectedNonce = make([]byte, 32)
	_, err := NewExperimentalVerifier().Verify(context.Background(), fixture.evidence, wrongNonce)
	requireErrorKind(t, err, ErrorFreshness)

	mutated := fixture.evidence
	mutated.SignedMeasurements = append([]byte(nil), fixture.evidence.SignedMeasurements...)
	mutated.SignedMeasurements[len(mutated.SignedMeasurements)-1] ^= 1
	_, err = NewExperimentalVerifier().Verify(context.Background(), mutated, fixture.policy)
	requireErrorKind(t, err, ErrorSignature)
}

func TestExperimentalVerifierDoesNotTrustCarriedRoot(t *testing.T) {
	fixture := newSPDMFixture(t, Version12, BaseHashSHA384, BaseAsymECDSAP384, elliptic.P384(), false)
	fixture.policy.Roots = nil
	fixture.policy.AuthorizedLeafKeys = nil

	result, err := NewExperimentalVerifier().Verify(context.Background(), fixture.evidence, fixture.policy)
	require.NoError(t, err)
	require.Equal(t, OutcomeIndeterminate, result.RootTrust)
	require.Equal(t, OutcomeIndeterminate, result.IdentityAuthorization)
}

func TestExperimentalVerifierLegacyReversedSignatureRequiresOptIn(t *testing.T) {
	fixture := newSPDMFixture(t, Version10, BaseHashSHA384, BaseAsymECDSAP384, elliptic.P384(), true)
	fixture.policy.AllowSPDM10ReversedECDSA = false
	_, err := NewExperimentalVerifier().Verify(context.Background(), fixture.evidence, fixture.policy)
	requireErrorKind(t, err, ErrorSignature)

	fixture.policy.AllowSPDM10ReversedECDSA = true
	result, err := NewExperimentalVerifier().Verify(context.Background(), fixture.evidence, fixture.policy)
	require.NoError(t, err)
	require.Equal(t, SignatureEncodingLegacyReversed, result.SignatureEncoding)
}

func TestExperimentalVerifierAuthenticatesBeforeSemanticRejection(t *testing.T) {
	fixture := newSPDMFixtureWithMeasurement(t, Version12, BaseHashSHA384, BaseAsymECDSAP384, elliptic.P384(), false, 1, 0x89)
	result, err := NewExperimentalVerifier().Verify(context.Background(), fixture.evidence, fixture.policy)
	requireErrorKind(t, err, ErrorUnsupported)
	require.NotNil(t, result)
	require.Equal(t, OutcomePass, result.RootTrust)
	require.Equal(t, OutcomePass, result.IdentityAuthorization)
	require.Equal(t, fixture.policy.ExpectedNonce, result.RequesterNonce)
	require.Equal(t, SignatureEncodingBigEndian, result.SignatureEncoding)
}

func TestExperimentalVerifierAllowsKnownTypesAcrossVersionsByPolicy(t *testing.T) {
	fixture := newSPDMFixtureWithMeasurement(t, Version12, BaseHashSHA384, BaseAsymECDSAP384, elliptic.P384(), false, 1, 0x89)
	fixture.policy.MeasurementTypePolicy = MeasurementTypePolicyKnownTypes
	result, err := NewExperimentalVerifier().Verify(context.Background(), fixture.evidence, fixture.policy)
	require.NoError(t, err)
	require.True(t, result.MeasurementTypeCompatibilityUsed)
	require.Equal(t, MeasurementTypeInformational, result.Measurements[0].ValueType)
}

func TestValidateMeasurementSemanticsVersionedTypes(t *testing.T) {
	for valueType := uint8(0); valueType <= MeasurementTypeFirmwareSVN; valueType++ {
		block := semanticTestBlock(valueType)
		_, err := validateMeasurementSemantics(Version12, []MeasurementBlock{block}, MeasurementTypePolicyVersionStrict)
		require.NoError(t, err, "type %d", valueType)
	}
	for valueType := MeasurementTypeHashExtend; valueType <= MeasurementTypeStructuredManifest; valueType++ {
		block := semanticTestBlock(valueType)
		_, err := validateMeasurementSemantics(Version12, []MeasurementBlock{block}, MeasurementTypePolicyVersionStrict)
		requireErrorKind(t, err, ErrorUnsupported)
		compatibilityUsed, err := validateMeasurementSemantics(Version12, []MeasurementBlock{block}, MeasurementTypePolicyKnownTypes)
		require.NoError(t, err, "type %d", valueType)
		require.True(t, compatibilityUsed)
		compatibilityUsed, err = validateMeasurementSemantics(Version13, []MeasurementBlock{block}, MeasurementTypePolicyVersionStrict)
		require.NoError(t, err, "type %d", valueType)
		require.False(t, compatibilityUsed)
	}
	unknown := semanticTestBlock(MeasurementTypeStructuredManifest + 1)
	_, err := validateMeasurementSemantics(Version13, []MeasurementBlock{unknown}, MeasurementTypePolicyKnownTypes)
	requireErrorKind(t, err, ErrorUnsupported)
}

func TestValidateMeasurementSemanticsRepresentationRules(t *testing.T) {
	tests := []MeasurementBlock{
		{Index: 1, MeasurementSpecification: measurementSpecificationDMTF, ValueType: MeasurementTypeDeviceMode},
		{Index: 1, MeasurementSpecification: measurementSpecificationDMTF, ValueType: MeasurementTypeHashExtend, RawBitStream: true},
		{Index: 1, MeasurementSpecification: measurementSpecificationDMTF, ValueType: MeasurementTypeInformational},
	}
	for _, block := range tests {
		_, err := validateMeasurementSemantics(Version13, []MeasurementBlock{block}, MeasurementTypePolicyKnownTypes)
		requireErrorKind(t, err, ErrorUnsupported)
	}
}

func TestValidateMeasurementSemanticsReservedIndices(t *testing.T) {
	for _, index := range []uint8{0, 0xf0, 0xfc, 0xff} {
		block := semanticTestBlock(MeasurementTypeImmutableROM)
		block.Index = index
		_, err := validateMeasurementSemantics(Version13, []MeasurementBlock{block}, MeasurementTypePolicyKnownTypes)
		requireErrorKind(t, err, ErrorUnsupported)
	}
	manifest := semanticTestBlock(MeasurementTypeManifest)
	manifest.Index = 0xfd
	_, err := validateMeasurementSemantics(Version12, []MeasurementBlock{manifest}, MeasurementTypePolicyVersionStrict)
	require.NoError(t, err)
	structured := semanticTestBlock(MeasurementTypeStructuredManifest)
	structured.Index = 0xfd
	_, err = validateMeasurementSemantics(Version13, []MeasurementBlock{structured}, MeasurementTypePolicyVersionStrict)
	require.NoError(t, err)
	_, err = validateMeasurementSemantics(Version12, []MeasurementBlock{structured}, MeasurementTypePolicyVersionStrict)
	requireErrorKind(t, err, ErrorUnsupported)
	compatibilityUsed, err := validateMeasurementSemantics(Version12, []MeasurementBlock{structured}, MeasurementTypePolicyKnownTypes)
	require.NoError(t, err)
	require.True(t, compatibilityUsed)
	deviceMode := semanticTestBlock(MeasurementTypeDeviceMode)
	deviceMode.Index = 0xfe
	_, err = validateMeasurementSemantics(Version12, []MeasurementBlock{deviceMode}, MeasurementTypePolicyVersionStrict)
	require.NoError(t, err)
	deviceMode.ValueType = MeasurementTypeMutableFirmware
	_, err = validateMeasurementSemantics(Version12, []MeasurementBlock{deviceMode}, MeasurementTypePolicyKnownTypes)
	requireErrorKind(t, err, ErrorUnsupported)
}

func semanticTestBlock(valueType uint8) MeasurementBlock {
	raw := valueType == MeasurementTypeDeviceMode || valueType == MeasurementTypeInformational
	return MeasurementBlock{Index: 1, MeasurementSpecification: measurementSpecificationDMTF, ValueType: valueType, RawBitStream: raw}
}

type spdmFixture struct {
	evidence Evidence
	policy   Policy
}

func newSPDMFixture(t *testing.T, version Version, hash BaseHashAlgorithm, asym BaseAsymAlgorithm, curve elliptic.Curve, reverseSignature bool) spdmFixture {
	return newSPDMFixtureWithMeasurement(t, version, hash, asym, curve, reverseSignature, 1, 0x81)
}

func newSPDMFixtureWithMeasurement(t *testing.T, version Version, hash BaseHashAlgorithm, asym BaseAsymAlgorithm, curve elliptic.Curve, reverseSignature bool, measurementIndex, measurementType uint8) spdmFixture {
	t.Helper()
	now := time.Date(2026, time.September, 16, 0, 0, 0, 0, time.UTC)
	rootKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic SPDM Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic SPDM Leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	nonce := make([]byte, 32)
	for index := range nonce {
		nonce[index] = byte(index)
	}
	vca := buildVCA(version, hash, asym)
	measurement := []byte("synthetic-firmware")
	blockValue := append([]byte{measurementType, byte(len(measurement)), 0}, measurement...)
	block := append([]byte{measurementIndex, measurementSpecificationDMTF, byte(len(blockValue)), 0}, blockValue...)
	request := append([]byte{byte(version), requestGetMeasurements, generateSignature, measurementOperationAll}, nonce...)
	if version >= Version11 {
		request = append(request, 0)
	}
	response := make([]byte, 0, 8+len(block)+32+2)
	response = append(response, byte(version), responseMeasurements, 0, 0, 1, byte(len(block)), 0, 0)
	response = append(response, block...)
	response = append(response, make([]byte, 32)...)
	response = append(response, 0, 0)
	transcript := append(append([]byte(nil), request...), response...)
	if version >= Version12 {
		transcript = append(append([]byte(nil), vca...), transcript...)
	}
	digest, err := transcriptDigest(version, hash, transcript)
	require.NoError(t, err)
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, digest)
	require.NoError(t, err)
	componentSize := (curve.Params().BitSize + 7) / 8
	signature := make([]byte, componentSize*2)
	r.FillBytes(signature[:componentSize])
	s.FillBytes(signature[componentSize:])
	if reverseSignature {
		reverseBytes(signature[:componentSize])
		reverseBytes(signature[componentSize:])
	}

	evidence := Evidence{
		SignedMeasurements:  append(transcript, signature...),
		CertificateChainDER: append(append([]byte(nil), rootDER...), leafDER...),
	}
	if version < Version12 {
		evidence.VCATranscript = vca
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return spdmFixture{evidence: evidence, policy: Policy{
		ExpectedNonce: nonce, AuthorizedLeafKeys: []crypto.PublicKey{&leafKey.PublicKey}, Roots: roots,
		CurrentTime: now, AllowSPDM10: true, AllowSPDM12: true,
		AllowedBaseHashes: []BaseHashAlgorithm{BaseHashSHA256, BaseHashSHA384},
		AllowedBaseAsym:   []BaseAsymAlgorithm{BaseAsymECDSAP256, BaseAsymECDSAP384},
	}}
}

func buildVCA(version Version, hash BaseHashAlgorithm, asym BaseAsymAlgorithm) []byte {
	versionResponse := []byte{byte(Version10), responseVersion, 0, 0, 0, 1, 0, byte(version)}
	requestCapabilitySize := 12
	responseCapabilitySize := 12
	if version == Version10 {
		requestCapabilitySize = 4
	}
	if version >= Version12 {
		requestCapabilitySize = 20
		responseCapabilitySize = 20
	}
	getCapabilities := make([]byte, requestCapabilitySize)
	copy(getCapabilities, []byte{byte(version), requestGetCapabilities, 0, 0})
	capabilities := make([]byte, responseCapabilitySize)
	copy(capabilities, []byte{byte(version), responseCapabilities, 0, 0})
	binary.LittleEndian.PutUint32(capabilities[8:12], 0x10)
	negotiate := make([]byte, 32)
	copy(negotiate, []byte{byte(version), requestNegotiateAlgorithms, 0, 0})
	binary.LittleEndian.PutUint16(negotiate[4:6], uint16(len(negotiate)))
	negotiate[6] = 1
	binary.LittleEndian.PutUint32(negotiate[8:12], baseAsymBits(asym))
	binary.LittleEndian.PutUint32(negotiate[12:16], baseHashBits(hash))
	algorithms := make([]byte, 36)
	copy(algorithms, []byte{byte(version), responseAlgorithms, 0, 0})
	binary.LittleEndian.PutUint16(algorithms[4:6], uint16(len(algorithms)))
	algorithms[6] = 1
	binary.LittleEndian.PutUint32(algorithms[8:12], measurementHashBits(hash))
	binary.LittleEndian.PutUint32(algorithms[12:16], baseAsymBits(asym))
	binary.LittleEndian.PutUint32(algorithms[16:20], baseHashBits(hash))
	result := []byte{byte(Version10), requestGetVersion, 0, 0}
	result = append(result, versionResponse...)
	result = append(result, getCapabilities...)
	result = append(result, capabilities...)
	result = append(result, negotiate...)
	return append(result, algorithms...)
}

func baseHashBits(algorithm BaseHashAlgorithm) uint32 {
	if algorithm == BaseHashSHA256 {
		return 1 << 0
	}
	return 1 << 1
}

func measurementHashBits(algorithm BaseHashAlgorithm) uint32 {
	if algorithm == BaseHashSHA256 {
		return 1 << 1
	}
	return 1 << 2
}

func baseAsymBits(algorithm BaseAsymAlgorithm) uint32 {
	if algorithm == BaseAsymECDSAP256 {
		return 1 << 4
	}
	return 1 << 7
}

func requireErrorKind(t *testing.T, err error, expected ErrorKind) {
	t.Helper()
	require.Error(t, err)
	var verificationErr *VerificationError
	require.ErrorAs(t, err, &verificationErr)
	require.Equal(t, expected, verificationErr.Kind)
}
