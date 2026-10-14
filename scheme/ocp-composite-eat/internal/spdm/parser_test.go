// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package spdm

import (
	"context"
	"crypto/elliptic"
	"encoding/binary"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseMeasurementBlocksRejectsDuplicateIndex(t *testing.T) {
	block := []byte{1, measurementSpecificationDMTF, 4, 0, 0x81, 1, 0, 0xaa}
	record := append(append([]byte(nil), block...), block...)
	_, err := parseMeasurementBlocks(record, 2, DefaultLimits())
	requireErrorKind(t, err, ErrorMalformed)
}

func TestParseMeasurementBlocksRejectsTruncationAndCountMismatch(t *testing.T) {
	truncated := []byte{1, measurementSpecificationDMTF, 4, 0, 0x81}
	_, err := parseMeasurementBlocks(truncated, 1, DefaultLimits())
	requireErrorKind(t, err, ErrorMalformed)

	block := []byte{1, measurementSpecificationDMTF, 4, 0, 0x81, 1, 0, 0xaa}
	_, err = parseMeasurementBlocks(block, 2, DefaultLimits())
	requireErrorKind(t, err, ErrorMalformed)
}

func TestLengthDelimitedMessageRejectsDeclaredOverflow(t *testing.T) {
	message := make([]byte, 32)
	copy(message, []byte{byte(Version12), requestNegotiateAlgorithms, 0, 0})
	binary.LittleEndian.PutUint16(message[4:6], 33)
	_, err := lengthDelimitedMessage(message, 0, Version12, requestNegotiateAlgorithms, 32)
	requireErrorKind(t, err, ErrorMalformed)
}

func TestVCAValidationAndLimits(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(value []byte) { value[4] = 0xff },
		func(value []byte) { value[11] = 0x12 },
		func(value []byte) { value[24] = 0 },
		func(value []byte) { value[36] = 0 },
		func(value []byte) { value[60] = 1 },
	} {
		fixture := newSPDMFixture(t, Version10, BaseHashSHA384, BaseAsymECDSAP384, elliptic.P384(), false)
		mutate(fixture.evidence.VCATranscript)
		_, err := NewExperimentalVerifier().Verify(context.Background(), fixture.evidence, fixture.policy)
		require.Error(t, err)
	}
	fixture := newSPDMFixture(t, Version12, BaseHashSHA384, BaseAsymECDSAP384, elliptic.P384(), false)
	verifier := NewExperimentalVerifier()
	verifier.Limits.MaxVCABytes = 1
	_, err := verifier.Verify(context.Background(), fixture.evidence, fixture.policy)
	require.ErrorContains(t, err, "VCA exceeds")
}

func TestUnsupportedMeasurementSpecification(t *testing.T) {
	_, err := parseMeasurementBlocks([]byte{1, 0x80, 1, 0, 0}, 1, DefaultLimits())
	requireErrorKind(t, err, ErrorUnsupported)
	blocks, err := parseMeasurementBlocks([]byte{1, 1, 4, 0, 0x8a, 1, 0, 0}, 1, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, MeasurementTypeStructuredManifest, blocks[0].ValueType)
	require.True(t, blocks[0].RawBitStream)
}
