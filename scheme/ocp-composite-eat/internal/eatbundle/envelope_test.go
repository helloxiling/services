// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package eatbundle

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestParsePreservesExactByteStrings(t *testing.T) {
	mainToken := []byte{0xd8, 0x3d, 0x80}
	claimsSet := []byte{0xb9, 0x00, 0x01, 0x19, 0x01, 0x2b, 0x83, 0x61, 0x78, 0x40, 0x04}
	encoded := encodeEnvelope(t, mainToken, map[string][]byte{"component/0": claimsSet})

	bundle, err := Parse(encoded, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, mainToken, bundle.MainToken)
	require.Equal(t, claimsSet, bundle.DetachedClaimsSets["component/0"])
}

func TestParseRejectsWrongShapeAndLimits(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxClaimsSetBytes = 1

	tests := map[string][]byte{
		"wrong tag":    mustEncode(t, cbor.Tag{Number: 601, Content: []any{[]byte{1}, map[string][]byte{"a": {1}}}}),
		"wrong slots":  mustEncode(t, cbor.Tag{Number: Tag, Content: []any{[]byte{1}}}),
		"empty token":  encodeEnvelope(t, nil, map[string][]byte{"a": {1}}),
		"empty map":    encodeEnvelope(t, []byte{1}, map[string][]byte{}),
		"oversize set": encodeEnvelope(t, []byte{1}, map[string][]byte{"a": {1, 2}}),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(encoded, limits)
			require.Error(t, err)
		})
	}
}

func TestParseRejectsDuplicateAndIndefiniteMaps(t *testing.T) {
	duplicateMap := []byte{0xd9, 0x02, 0x5a, 0x82, 0x41, 0x01, 0xa2, 0x61, 0x61, 0x41, 0x01, 0x61, 0x61, 0x41, 0x02}
	indefiniteMap := []byte{0xd9, 0x02, 0x5a, 0x82, 0x41, 0x01, 0xbf, 0x61, 0x61, 0x41, 0x01, 0xff}

	_, err := Parse(duplicateMap, DefaultLimits())
	require.Error(t, err)
	_, err = Parse(indefiniteMap, DefaultLimits())
	require.Error(t, err)
}

func FuzzParse(f *testing.F) {
	f.Add(encodeEnvelope(f, []byte{1}, map[string][]byte{"component/0": {0xa0}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data, DefaultLimits())
	})
}

type testingT interface {
	Helper()
	Fatalf(string, ...any)
}

func encodeEnvelope(t testingT, mainToken []byte, claimsSets map[string][]byte) []byte {
	t.Helper()
	return encode(t, cbor.Tag{Number: Tag, Content: []any{mainToken, claimsSets}})
}

func mustEncode(t testingT, value any) []byte {
	t.Helper()
	return encode(t, value)
}

func encode(t testingT, value any) []byte {
	t.Helper()
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("create encoding mode: %v", err)
	}
	encoded, err := mode.Marshal(value)
	if err != nil {
		t.Fatalf("encode test value: %v", err)
	}
	return encoded
}
