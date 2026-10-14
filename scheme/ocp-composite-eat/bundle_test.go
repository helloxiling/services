// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"crypto/sha512"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestParseBundleAndVerifyExactDetachedBytes(t *testing.T) {
	claimsSet := mustEncode(t, map[int64]any{
		299: []any{"application/eat+cwt", []byte{0x01, 0x02}, uint64(4)},
	})
	bundleBytes := mustEncode(t, cbor.Tag{
		Number: detachedEATBundleTag,
		Content: []any{
			[]byte{0xd8, 0x3d, 0x80},
			map[string]any{"env.device.0": claimsSet},
		},
	})

	bundle, err := ParseBundle(bundleBytes, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, []byte{0xd8, 0x3d, 0x80}, bundle.MainToken)

	digest := sha512.Sum384(claimsSet)
	require.NoError(t, bundle.VerifyDetachedDigests(map[string]DetachedDigest{
		"env.device.0": {Algorithm: sha384COSEAlgorithm, Value: digest[:]},
	}))

	equivalentButDifferent := append([]byte{0xb9, 0x00, 0x01}, claimsSet[1:]...)
	wrongDigest := sha512.Sum384(equivalentButDifferent)
	require.ErrorContains(t, bundle.VerifyDetachedDigests(map[string]DetachedDigest{
		"env.device.0": {Algorithm: sha384COSEAlgorithm, Value: wrongDigest[:]},
	}), "digest mismatch")
}

func TestParseBundleRejectsNonDeterministicClaimsSet(t *testing.T) {
	nonDeterministic := []byte{0xb9, 0x00, 0x01, 0x19, 0x01, 0x2b, 0x83, 0x61, 0x78, 0x40, 0x04}
	bundleBytes := mustEncode(t, cbor.Tag{
		Number: detachedEATBundleTag,
		Content: []any{
			[]byte{0x01},
			map[string]any{"env.device.0": nonDeterministic},
		},
	})

	_, err := ParseBundle(bundleBytes, DefaultLimits())
	require.ErrorContains(t, err, "not core deterministic CBOR")
}

func TestParseBundleAcceptsDirectMapClaimsSet(t *testing.T) {
	claimsSet := mustEncode(t, map[string]any{
		"signed_measurements": []byte{0x01},
		"cert_chain":          []byte{0x02},
	})
	bundleBytes := mustEncode(t, cbor.Tag{
		Number:  detachedEATBundleTag,
		Content: []any{[]byte{0x01}, map[string]any{"env.device.0": claimsSet}},
	})

	bundle, err := ParseBundle(bundleBytes, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, claimsSet, bundle.DetachedClaimsSets["env.device.0"])
}

func TestParseBundleRejectsInvalidEnvironmentID(t *testing.T) {
	claimsSet := mustEncode(t, map[int64]any{299: []any{"x", []byte{}, uint64(4)}})
	bundleBytes := mustEncode(t, cbor.Tag{
		Number:  detachedEATBundleTag,
		Content: []any{[]byte{0x01}, map[string]any{"nic.0": claimsSet}},
	})

	_, err := ParseBundle(bundleBytes, DefaultLimits())
	require.ErrorContains(t, err, "invalid Target Environment Identifier")
}

func TestVerifyDetachedDigestsRejectsKeySetMismatch(t *testing.T) {
	bundle := Bundle{DetachedClaimsSets: map[string][]byte{"env.device.0": {0xa1}}}
	err := bundle.VerifyDetachedDigests(map[string]DetachedDigest{})
	require.ErrorContains(t, err, "key counts differ")
}

func mustEncode(t *testing.T, value any) []byte {
	t.Helper()
	encMode, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	data, err := encMode.Marshal(value)
	require.NoError(t, err)
	return data
}
