// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"github.com/veraison/services/scheme/ocp-composite-eat/internal/evidencecarriage"
)

const (
	cmwClaim              = 299
	spdmEvidenceMediaType = evidencecarriage.SPDMEvidenceMediaType
)

func DecodeNativeEvidence(claimsSet []byte, carriage, mediaType string, limits Limits) (*evidencecarriage.DecodedEvidence, error) {
	return evidencecarriage.Decode(claimsSet, carriage, mediaType, evidencecarriage.Limits{
		MaxRecordBytes: limits.MaxClaimsSetBytes, MaxValueBytes: limits.MaxClaimsSetBytes,
		MaxNestedLevels: limits.MaxNestedLevels,
	})
}
