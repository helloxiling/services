// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package evidencecarriage

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/veraison/cmw"
)

func TestDecodeCMWSPDM(t *testing.T) {
	native := encodeValue(t, []any{[]byte{1}, []byte{2}, []byte{3}})
	claimsSet := encodeValue(t, map[int64]any{
		cmwClaim: []any{SPDMEvidenceMediaType, native, uint64(cmw.Evidence)},
	})

	decoded, err := Decode(claimsSet, CMWEncoding, SPDMEvidenceMediaType, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, CMWEncoding, decoded.Carriage)
	require.Equal(t, []byte{1}, decoded.SPDM.SignedMeasurements)
	require.Equal(t, []byte{2}, decoded.SPDM.CertificateChainDER)
	require.Equal(t, []byte{3}, decoded.SPDM.VCATranscript)
	require.Nil(t, decoded.DeviceEAT)
}

func TestDecodeCMWRejectsOpenOrWrongSchema(t *testing.T) {
	native := encodeValue(t, []any{[]byte{1}, []byte{2}})
	record := []any{SPDMEvidenceMediaType, native, uint64(cmw.Evidence)}
	for name, claimsSet := range map[string][]byte{
		"additional claim": encodeValue(t, map[int64]any{cmwClaim: record, 300: true}),
		"direct map":       encodeValue(t, map[string]any{"signed_measurements": []byte{1}, "cert_chain": []byte{2}}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(claimsSet, CMWEncoding, SPDMEvidenceMediaType, DefaultLimits())
			require.Error(t, err)
		})
	}
}

func TestDecodeDirectMapSPDM(t *testing.T) {
	claimsSet := encodeValue(t, map[string]any{
		"signed_measurements": []byte{1},
		"cert_chain":          []byte{2},
	})
	decoded, err := Decode(claimsSet, DirectMap, SPDMEvidenceMediaType, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, DirectMap, decoded.Carriage)
	require.Equal(t, []byte{1}, decoded.SPDM.SignedMeasurements)
	require.Equal(t, []byte{2}, decoded.SPDM.CertificateChainDER)
	require.Nil(t, decoded.DeviceEAT)
}

func TestDecodeDirectMapDeviceEAT(t *testing.T) {
	const mediaType = "application/eat+cwt"
	claimsSet := encodeValue(t, map[string]any{
		"token_format": mediaType,
		"device_token": []byte{1, 2},
	})
	decoded, err := Decode(claimsSet, DirectMap, mediaType, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, decoded.DeviceEAT)
	require.Nil(t, decoded.SPDM)
}

func TestDecodeDirectMapRejectsUnknownTypedAndMixedShapes(t *testing.T) {
	for name, claimsSet := range map[string][]byte{
		"unknown": encodeValue(t, map[string]any{
			"signed_measurements": []byte{1}, "cert_chain": []byte{2}, "other": []byte{3},
		}),
		"typed wrapper": encodeValue(t, map[string]any{
			"signed_measurements": []any{"application/octet-stream", []byte{1}}, "cert_chain": []byte{2},
		}),
		"CMW": encodeValue(t, map[int64]any{
			cmwClaim: []any{SPDMEvidenceMediaType, []byte{1}, uint64(cmw.Evidence)},
		}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(claimsSet, DirectMap, SPDMEvidenceMediaType, DefaultLimits())
			require.Error(t, err)
		})
	}
}

func TestDecodeDirectMapRejectsDuplicateKeys(t *testing.T) {
	claimsSet := []byte{
		0xa3,
		0x73, 's', 'i', 'g', 'n', 'e', 'd', '_', 'm', 'e', 'a', 's', 'u', 'r', 'e', 'm', 'e', 'n', 't', 's', 0x41, 0x01,
		0x6a, 'c', 'e', 'r', 't', '_', 'c', 'h', 'a', 'i', 'n', 0x41, 0x02,
		0x6a, 'c', 'e', 'r', 't', '_', 'c', 'h', 'a', 'i', 'n', 0x41, 0x03,
	}
	_, err := Decode(claimsSet, DirectMap, SPDMEvidenceMediaType, DefaultLimits())
	require.Error(t, err)
}

func TestDecodeDoesNotFallback(t *testing.T) {
	claimsSet := encodeValue(t, map[string]any{
		"signed_measurements": []byte{1},
		"cert_chain":          []byte{2},
	})
	_, err := Decode(claimsSet, CMWEncoding, SPDMEvidenceMediaType, DefaultLimits())
	require.Error(t, err)
	_, err = Decode(claimsSet, "unknown", SPDMEvidenceMediaType, DefaultLimits())
	require.ErrorContains(t, err, "unsupported Evidence carriage")
}

func encodeValue(t *testing.T, value any) []byte {
	t.Helper()
	mode, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	encoded, err := mode.Marshal(value)
	require.NoError(t, err)
	return encoded
}
