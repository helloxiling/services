// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package evidencecarriage

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/cmw"
)

type Limits struct {
	MaxRecordBytes  int
	MaxValueBytes   int
	MaxNestedLevels int
}

func DefaultLimits() Limits {
	return Limits{
		MaxRecordBytes:  1024 * 1024,
		MaxValueBytes:   1024 * 1024,
		MaxNestedLevels: 16,
	}
}

type Record struct {
	MediaType string
	Value     []byte
	Indicator cmw.Indicator
}

func ParseRecord(data []byte, limits Limits) (*Record, error) {
	if limits.MaxRecordBytes <= 0 || limits.MaxValueBytes <= 0 {
		return nil, errors.New("Record CMW limits must be positive")
	}
	if limits.MaxNestedLevels < 4 {
		return nil, errors.New("maximum nested levels must be at least 4")
	}
	if len(data) == 0 {
		return nil, errors.New("Record CMW is empty")
	}
	if len(data) > limits.MaxRecordBytes {
		return nil, fmt.Errorf("Record CMW exceeds %d-byte limit", limits.MaxRecordBytes)
	}

	decMode, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxArrayElements: 16,
		MaxMapPairs:      16,
		MaxNestedLevels:  limits.MaxNestedLevels,
	}.DecMode()
	if err != nil {
		return nil, err
	}
	var fields []cbor.RawMessage
	if err := decMode.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("decode Record CMW: %w", err)
	}
	if len(fields) != 3 {
		return nil, fmt.Errorf("Record CMW must contain exactly three fields, got %d", len(fields))
	}

	var explicitMediaType string
	if err := decMode.Unmarshal(fields[0], &explicitMediaType); err != nil || explicitMediaType == "" {
		return nil, errors.New("Record CMW type must be an explicit media-type string")
	}
	var value []byte
	if err := decMode.Unmarshal(fields[1], &value); err != nil || len(value) == 0 {
		return nil, errors.New("Record CMW value must be a non-empty byte string")
	}
	if len(value) > limits.MaxValueBytes {
		return nil, fmt.Errorf("Record CMW value exceeds %d-byte limit", limits.MaxValueBytes)
	}

	var wrapped cmw.CMW
	if err := wrapped.Deserialize(data); err != nil {
		return nil, fmt.Errorf("decode Record CMW with veraison/cmw: %w", err)
	}
	if wrapped.GetKind() != cmw.KindMonad || wrapped.GetFormat() != cmw.FormatCBORRecord {
		return nil, errors.New("native Evidence must use a Record CMW")
	}
	mediaType, err := wrapped.GetMonadType()
	if err != nil {
		return nil, err
	}
	wrappedValue, err := wrapped.GetMonadValue()
	if err != nil {
		return nil, err
	}
	indicator, err := wrapped.GetMonadIndicator()
	if err != nil {
		return nil, err
	}
	if indicator != cmw.Evidence {
		return nil, fmt.Errorf("Record CMW indicator must identify only Evidence (%d), got %d", cmw.Evidence, indicator)
	}

	return &Record{MediaType: mediaType, Value: wrappedValue, Indicator: indicator}, nil
}
