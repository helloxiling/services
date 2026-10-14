// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package evidencecarriage

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const cmwClaim = 299

func DecodeCMW(claimsSet []byte, _ string, limits Limits) (*DecodedEvidence, error) {
	if len(claimsSet) == 0 || len(claimsSet) > limits.MaxRecordBytes {
		return nil, fmt.Errorf("detached Claims-Set size is outside the allowed range")
	}
	mode, err := decodingMode(limits)
	if err != nil {
		return nil, err
	}
	if err := requireDeterministic(claimsSet, mode); err != nil {
		return nil, fmt.Errorf("detached Claims-Set encoding: %w", err)
	}
	var claims map[int64]cbor.RawMessage
	if err := mode.Unmarshal(claimsSet, &claims); err != nil {
		return nil, fmt.Errorf("decode detached Claims-Set: %w", err)
	}
	if len(claims) != 1 {
		return nil, fmt.Errorf("CMW Claims-Set must contain exactly claim %d", cmwClaim)
	}
	raw, ok := claims[cmwClaim]
	if !ok {
		return nil, fmt.Errorf("CMW Claims-Set is missing claim %d", cmwClaim)
	}
	record, err := ParseRecord(raw, limits)
	if err != nil {
		return nil, err
	}
	result := &DecodedEvidence{Carriage: CMWEncoding, MediaType: record.MediaType}
	if record.MediaType == SPDMEvidenceMediaType {
		result.SPDM, err = decodeSPDMRecord(record.Value, mode)
		if err != nil {
			return nil, err
		}
	} else {
		if len(record.Value) == 0 {
			return nil, errors.New("device EAT is empty")
		}
		result.DeviceEAT = append([]byte(nil), record.Value...)
	}
	return result, nil
}
