// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package evidencecarriage

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/veraison/cmw"
)

func TestParseRecord(t *testing.T) {
	value := []byte{0xd8, 0x3d, 0x80}
	encoded := encodeRecord(t, []any{"application/eat+cwt", value, uint64(cmw.Evidence)})

	record, err := ParseRecord(encoded, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, "application/eat+cwt", record.MediaType)
	require.Equal(t, value, record.Value)
	require.Equal(t, cmw.Indicator(cmw.Evidence), record.Indicator)
}

func TestParseRecordRejectsInvalidFields(t *testing.T) {
	tests := map[string][]any{
		"missing indicator": {"application/eat+cwt", []byte{1}},
		"numeric type":      {uint64(10571), []byte{1}, uint64(cmw.Evidence)},
		"empty type":        {"", []byte{1}, uint64(cmw.Evidence)},
		"empty value":       {"application/eat+cwt", []byte{}, uint64(cmw.Evidence)},
		"wrong indicator":   {"application/eat+cwt", []byte{1}, uint64(cmw.ReferenceValues)},
		"mixed indicator":   {"application/eat+cwt", []byte{1}, uint64(cmw.Evidence | cmw.Endorsements)},
	}
	for name, fields := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRecord(encodeRecord(t, fields), DefaultLimits())
			require.Error(t, err)
		})
	}
}

func TestParseRecordEnforcesValueLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxValueBytes = 1
	_, err := ParseRecord(encodeRecord(t, []any{
		"application/eat+cwt", []byte{1, 2}, uint64(cmw.Evidence),
	}), limits)
	require.ErrorContains(t, err, "value exceeds")
}

func FuzzParseRecord(f *testing.F) {
	f.Add(encodeRecord(f, []any{"application/eat+cwt", []byte{1}, uint64(cmw.Evidence)}))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRecord(data, DefaultLimits())
	})
}

type testingT interface {
	Helper()
	Fatalf(string, ...any)
}

func encodeRecord(t testingT, fields []any) []byte {
	t.Helper()
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("create encoding mode: %v", err)
	}
	encoded, err := mode.Marshal(fields)
	if err != nil {
		t.Fatalf("encode test Record CMW: %v", err)
	}
	return encoded
}
