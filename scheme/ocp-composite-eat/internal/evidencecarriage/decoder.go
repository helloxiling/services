// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package evidencecarriage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/services/scheme/ocp-composite-eat/internal/spdm"
)

const (
	CMWEncoding           = "cmw-encoding"
	DirectMap             = "direct-map"
	SPDMEvidenceMediaType = "application/spdm-evidence+cbor"
)

type DecodedEvidence struct {
	Carriage  string
	MediaType string
	SPDM      *spdm.Evidence
	DeviceEAT []byte
}

func Decode(claimsSet []byte, carriage, expectedMediaType string, limits Limits) (*DecodedEvidence, error) {
	if expectedMediaType == "" {
		return nil, errors.New("expected native Evidence media type is required")
	}
	switch carriage {
	case CMWEncoding:
		return DecodeCMW(claimsSet, expectedMediaType, limits)
	case DirectMap:
		return DecodeDirectMap(claimsSet, expectedMediaType, limits)
	default:
		return nil, fmt.Errorf("unsupported Evidence carriage %q", carriage)
	}
}

func decodingMode(limits Limits) (cbor.DecMode, error) {
	if limits.MaxNestedLevels < 4 {
		return nil, errors.New("maximum nested levels must be at least 4")
	}
	return cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxArrayElements: 16,
		MaxMapPairs:      16,
		MaxNestedLevels:  limits.MaxNestedLevels,
	}.DecMode()
}

func requireDeterministic(data []byte, mode cbor.DecMode) error {
	var value any
	if err := mode.Unmarshal(data, &value); err != nil {
		return err
	}
	encMode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return err
	}
	reencoded, err := encMode.Marshal(value)
	if err != nil {
		return err
	}
	if !bytes.Equal(reencoded, data) {
		return errors.New("not core deterministic CBOR")
	}
	return nil
}

func decodeSPDMRecord(data []byte, mode cbor.DecMode) (*spdm.Evidence, error) {
	var fields []cbor.RawMessage
	if err := mode.Unmarshal(data, &fields); err != nil || (len(fields) != 2 && len(fields) != 3) {
		return nil, errors.New("invalid SPDM evidence: expected signed measurements, certificate chain, and optional VCA")
	}
	evidence := &spdm.Evidence{}
	if err := decodeNonEmptyBytes(mode, fields[0], &evidence.SignedMeasurements, "SPDM signed measurements"); err != nil {
		return nil, err
	}
	if err := decodeNonEmptyBytes(mode, fields[1], &evidence.CertificateChainDER, "SPDM certificate chain"); err != nil {
		return nil, err
	}
	if len(fields) == 3 {
		if err := decodeNonEmptyBytes(mode, fields[2], &evidence.VCATranscript, "SPDM VCA"); err != nil {
			return nil, err
		}
	}
	return evidence, nil
}

func decodeNonEmptyBytes(mode cbor.DecMode, raw cbor.RawMessage, destination *[]byte, name string) error {
	if err := mode.Unmarshal(raw, destination); err != nil || len(*destination) == 0 {
		return fmt.Errorf("invalid %s: expected a non-empty byte string", name)
	}
	return nil
}
