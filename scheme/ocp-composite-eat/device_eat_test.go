// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/coev"
	"github.com/veraison/corim/comid"
)

func TestVerifyCaliptraDeviceEATAndAppraise(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	expectation := snapshot.Members["env.device.0"]
	nonce := testNonce()
	token := buildCaliptraDeviceToken(t, fixture.deviceKey, nonce, expectation)

	claims, err := VerifyCaliptraDeviceEAT(token, nonce, expectation, DefaultLimits())
	require.NoError(t, err)
	result := AppraiseMeasurements(expectation.ReferenceValues, claims.EvidenceTriples)
	require.True(t, result.Passed, result.Reason)
}

func TestMatchMeasurementsChecksMeasurementName(t *testing.T) {
	required := comid.MustNewMeasurement(uint(1), comid.UintType)
	required.SetName("mutable-firmware")
	required.SetRawValueBytes([]byte("same-value"), nil)
	observed := comid.MustNewMeasurement(uint(1), comid.UintType)
	observed.SetName("hardware-configuration")
	observed.SetRawValueBytes([]byte("same-value"), nil)
	result := matchMeasurements([]comid.Measurement{*required}, []comid.Measurement{*observed})
	require.False(t, result.Passed)
	require.Contains(t, result.Reason, "type mismatch")
}

func TestVerifyCaliptraDeviceEATRejectsWrongNonce(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	expectation := snapshot.Members["env.device.0"]
	token := buildCaliptraDeviceToken(t, fixture.deviceKey, testNonce(), expectation)

	_, err = VerifyCaliptraDeviceEAT(token, make([]byte, 32), expectation, DefaultLimits())
	require.ErrorContains(t, err, "nonce does not match")
}

func TestExtractDeviceEAT(t *testing.T) {
	token := []byte{1, 2, 3}
	claimsSet := mustEncode(t, map[int64]any{
		cmwClaim: []any{eatContentType, token, uint64(4)},
	})
	actual, err := ExtractDeviceEAT(claimsSet, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, token, actual)
}

func TestMeasurementConstraintsFailClosed(t *testing.T) {
	required := comid.MustNewMeasurement("firmware", comid.StringType).AddDigest(comid.Sha384, make([]byte, 48))
	observed := comid.MustNewMeasurement("firmware", comid.StringType).AddDigest(comid.Sha384, make([]byte, 48))
	required.SetRawValueBytes([]byte("approved"), nil)
	observed.SetRawValueBytes([]byte("rejected"), nil)
	require.False(t, matchMeasurements([]comid.Measurement{*required}, []comid.Measurement{*observed}).Passed)
	required.SetMinSVN(2)
	observed.SetSVN(1)
	require.Equal(t, OutcomeUnsupported, matchMeasurements([]comid.Measurement{*required}, []comid.Measurement{*observed}).Unresolved)
	require.Equal(t, OutcomeIndeterminate, AppraiseMeasurements(nil, nil).Unresolved)
	plain := comid.MustNewMeasurement("firmware", comid.StringType).AddDigest(comid.Sha384, make([]byte, 48))
	require.False(t, matchMeasurements([]comid.Measurement{*plain}, []comid.Measurement{*plain, *plain}).Passed)
}

func TestSHA512AndFlagConstraints(t *testing.T) {
	required := comid.MustNewMeasurement("boot-register", comid.StringType).AddDigest(comid.Sha512, make([]byte, 64))
	required.Val.Flags = comid.NewFlagsMap()
	required.Val.Flags.SetTrue(comid.FlagIsIntegrityProtected, comid.FlagIsImmutable)
	required.Val.Flags.SetFalse(comid.FlagIsDebug)
	observed := comid.MustNewMeasurement("boot-register", comid.StringType).AddDigest(comid.Sha512, make([]byte, 64))
	observed.Val.Flags = comid.NewFlagsMap()
	observed.Val.Flags.SetTrue(comid.FlagIsIntegrityProtected, comid.FlagIsImmutable, comid.FlagIsTcb)
	observed.Val.Flags.SetFalse(comid.FlagIsDebug)
	check := func() MeasurementAppraisal {
		return matchMeasurements([]comid.Measurement{*required}, []comid.Measurement{*observed})
	}
	require.True(t, check().Passed)
	observed.Val.Flags.SetTrue(comid.FlagIsDebug)
	require.False(t, check().Passed)
	observed.Val.Flags.Clear(comid.FlagIsDebug)
	require.False(t, check().Passed)
	observed.Val.Flags = nil
	require.False(t, check().Passed)
}

func TestDigestAlgorithmEncodingEquivalence(t *testing.T) {
	for _, algorithm := range []int{comid.Sha256, comid.Sha384, comid.Sha512} {
		reference := make(comid.Digests, 0, 2)
		reference = append(reference, *comid.NewDigestIntAlg(algorithm, []byte{1}))
		observed := comid.Digests{*comid.NewDigest(comid.StringDigestAlgorithm(comid.IntDigestAlgorithm(algorithm).String()), []byte{1})}
		require.True(t, normalizedDigests(observed).CompareAgainstReference(normalizedDigests(reference)))
		require.True(t, observed[0].Algorithm.IsString())
		conflict := *comid.NewDigest(observed[0].Algorithm, []byte{2})
		reference = append(reference, conflict)
		require.False(t, normalizedDigests(observed).CompareAgainstReference(normalizedDigests(reference)))
	}
}

func buildCaliptraDeviceToken(
	t *testing.T,
	key *ecdsa.PrivateKey,
	nonce []byte,
	expectation MemberExpectation,
) []byte {
	t.Helper()
	concise := coev.NewConciseEvidence()
	triples := coev.NewEvTriples()
	for index := range expectation.ReferenceValues {
		triple := expectation.ReferenceValues[index]
		triples.AddEvidenceTriple(&triple)
	}
	require.NoError(t, concise.AddTriples(triples))
	tagged, err := coev.NewTaggedConciseEvidence(concise)
	require.NoError(t, err)
	encodedEvidence, err := tagged.ToCBOR()
	require.NoError(t, err)

	payload := mustEncode(t, map[int64]any{
		claimNonce:        nonce,
		claimDebugStatus:  uint64(1),
		claimProfile:      cbor.Tag{Number: oidTag, Content: []byte(deviceEATProfile)},
		claimMeasurements: []any{[]any{uint64(conciseEvidenceFormat), encodedEvidence}},
	})
	protected := mustEncode(t, map[int64]any{headerAlgorithm: int64(es384COSEAlgorithm)})
	sigStructure := mustEncode(t, []any{"Signature1", protected, []byte{}, payload})
	digest := sha512.Sum384(sigStructure)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])

	keyID := sha512.Sum384(ellipticPublicKeyBytes(t, key))
	return mustEncode(t, cbor.Tag{Number: cborSelfDescribeTag, Content: cbor.Tag{
		Number: cwtTag, Content: cbor.Tag{Number: coseSign1Tag, Content: []any{
			protected, map[int64]any{headerKeyID: keyID[:]}, payload, signature,
		}},
	}})
}

func ellipticPublicKeyBytes(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	encoded, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	return append([]byte(nil), encoded[1:]...)
}

func testNonce() []byte {
	nonce := make([]byte, 32)
	for index := range nonce {
		nonce[index] = byte(0xa0 + index)
	}
	return nonce
}
