// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package eatbundle

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const Tag = 602

type Envelope struct {
	MainToken          []byte
	DetachedClaimsSets map[string][]byte
}

func Parse(data []byte, limits Limits) (*Envelope, error) {
	if err := validateLimits(limits); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("bundle is empty")
	}
	if len(data) > limits.MaxBundleBytes {
		return nil, fmt.Errorf("bundle exceeds %d-byte limit", limits.MaxBundleBytes)
	}

	decMode, err := decodeMode(limits)
	if err != nil {
		return nil, err
	}
	var tagged cbor.RawTag
	if err := decMode.Unmarshal(data, &tagged); err != nil {
		return nil, fmt.Errorf("decode bundle tag: %w", err)
	}
	if tagged.Number != Tag {
		return nil, fmt.Errorf("unexpected bundle tag %d", tagged.Number)
	}

	var slots []cbor.RawMessage
	if err := decMode.Unmarshal(tagged.Content, &slots); err != nil {
		return nil, fmt.Errorf("decode bundle slots: %w", err)
	}
	if len(slots) != 2 {
		return nil, fmt.Errorf("bundle must contain exactly two slots, got %d", len(slots))
	}

	var mainToken []byte
	if err := decMode.Unmarshal(slots[0], &mainToken); err != nil {
		return nil, fmt.Errorf("decode main-token: %w", err)
	}
	if len(mainToken) == 0 {
		return nil, errors.New("main-token is empty")
	}

	var detached map[string][]byte
	if err := decMode.Unmarshal(slots[1], &detached); err != nil {
		return nil, fmt.Errorf("decode detached Claims-Set map: %w", err)
	}
	if len(detached) == 0 {
		return nil, errors.New("detached Claims-Set map is empty")
	}
	if len(detached) > limits.MaxSubmodules {
		return nil, fmt.Errorf("submodule count exceeds limit %d", limits.MaxSubmodules)
	}
	for label, claimsSet := range detached {
		if label == "" {
			return nil, errors.New("detached Claims-Set label is empty")
		}
		if len(claimsSet) == 0 {
			return nil, fmt.Errorf("detached Claims-Set %q is empty", label)
		}
		if len(claimsSet) > limits.MaxClaimsSetBytes {
			return nil, fmt.Errorf("detached Claims-Set %q exceeds %d-byte limit", label, limits.MaxClaimsSetBytes)
		}
	}

	return &Envelope{MainToken: mainToken, DetachedClaimsSets: detached}, nil
}

func validateLimits(limits Limits) error {
	if limits.MaxBundleBytes <= 0 || limits.MaxClaimsSetBytes <= 0 || limits.MaxSubmodules <= 0 {
		return errors.New("bundle limits must be positive")
	}
	if limits.MaxNestedLevels < 4 {
		return errors.New("maximum nested levels must be at least 4")
	}
	return nil
}

func decodeMode(limits Limits) (cbor.DecMode, error) {
	maxMapPairs := limits.MaxSubmodules
	if maxMapPairs < 16 {
		maxMapPairs = 16
	}
	return cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsAllowed,
		MaxArrayElements: 16,
		MaxMapPairs:      maxMapPairs,
		MaxNestedLevels:  limits.MaxNestedLevels,
	}.DecMode()
}
