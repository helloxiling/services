// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package evidencecarriage

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/services/scheme/ocp-composite-eat/internal/spdm"
)

func DecodeDirectMap(claimsSet []byte, expectedMediaType string, limits Limits) (*DecodedEvidence, error) {
	if len(claimsSet) == 0 || len(claimsSet) > limits.MaxRecordBytes {
		return nil, errors.New("detached Claims-Set size is outside the allowed range")
	}
	mode, err := decodingMode(limits)
	if err != nil {
		return nil, err
	}
	if err := requireDeterministic(claimsSet, mode); err != nil {
		return nil, fmt.Errorf("detached Claims-Set encoding: %w", err)
	}
	var fields map[string]cbor.RawMessage
	if err := mode.Unmarshal(claimsSet, &fields); err != nil {
		return nil, fmt.Errorf("decode direct-map Claims-Set: %w", err)
	}
	result := &DecodedEvidence{Carriage: DirectMap, MediaType: expectedMediaType}
	if expectedMediaType == SPDMEvidenceMediaType {
		result.SPDM, err = decodeDirectSPDM(fields, mode)
	} else {
		result.DeviceEAT, err = decodeDirectDeviceEAT(fields, expectedMediaType, mode)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func decodeDirectSPDM(fields map[string]cbor.RawMessage, mode cbor.DecMode) (*spdm.Evidence, error) {
	if len(fields) < 2 || len(fields) > 3 {
		return nil, errors.New("direct-map SPDM Claims-Set must contain signed_measurements, cert_chain, and optional vca")
	}
	for key := range fields {
		if key != "signed_measurements" && key != "cert_chain" && key != "vca" {
			return nil, fmt.Errorf("unknown direct-map SPDM claim %q", key)
		}
	}
	evidence := &spdm.Evidence{}
	if err := decodeNonEmptyBytes(mode, fields["signed_measurements"], &evidence.SignedMeasurements, "SPDM signed measurements"); err != nil {
		return nil, err
	}
	if err := decodeNonEmptyBytes(mode, fields["cert_chain"], &evidence.CertificateChainDER, "SPDM certificate chain"); err != nil {
		return nil, err
	}
	if raw, ok := fields["vca"]; ok {
		if err := decodeNonEmptyBytes(mode, raw, &evidence.VCATranscript, "SPDM VCA"); err != nil {
			return nil, err
		}
	}
	return evidence, nil
}

func decodeDirectDeviceEAT(fields map[string]cbor.RawMessage, expectedMediaType string, mode cbor.DecMode) ([]byte, error) {
	if len(fields) != 2 {
		return nil, errors.New("direct-map Device EAT Claims-Set must contain exactly token_format and device_token")
	}
	for key := range fields {
		if key != "token_format" && key != "device_token" {
			return nil, fmt.Errorf("unknown direct-map Device EAT claim %q", key)
		}
	}
	var tokenFormat string
	if err := mode.Unmarshal(fields["token_format"], &tokenFormat); err != nil || tokenFormat == "" {
		return nil, errors.New("direct-map token_format must be a non-empty text string")
	}
	if tokenFormat != expectedMediaType {
		return nil, fmt.Errorf("direct-map token format %q does not match signed policy %q", tokenFormat, expectedMediaType)
	}
	var token []byte
	if err := decodeNonEmptyBytes(mode, fields["device_token"], &token, "Device EAT token"); err != nil {
		return nil, err
	}
	return token, nil
}
