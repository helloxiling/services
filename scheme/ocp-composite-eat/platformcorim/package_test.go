// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platformcorim

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateCompatibility(t *testing.T) {
	const sourceID = "tag:example.com,2026:released-component-reference"
	digests := map[string]string{sourceID: "0123456789abcdef"}
	policy := CompatibilityPolicy{EvidenceCarriageBySource: map[string]CarriageAuthorization{
		sourceID: {SourceSHA256: digests[sourceID], Carriage: CarriageDirectMap},
	}}
	require.NoError(t, ValidateCompatibility(policy, digests))

	authorization := policy.EvidenceCarriageBySource[sourceID]
	authorization.SourceSHA256 = "different"
	policy.EvidenceCarriageBySource[sourceID] = authorization
	require.ErrorContains(t, ValidateCompatibility(policy, digests), "source digest mismatch")

	policy.EvidenceCarriageBySource = map[string]CarriageAuthorization{
		"unknown": {SourceSHA256: "different", Carriage: CarriageDirectMap},
	}
	require.ErrorContains(t, ValidateCompatibility(policy, digests), "unknown component source")

	policy.EvidenceCarriageBySource = map[string]CarriageAuthorization{
		sourceID: {SourceSHA256: digests[sourceID], Carriage: CarriageCMW},
	}
	require.ErrorContains(t, ValidateCompatibility(policy, digests), "unsupported carriage")
}
