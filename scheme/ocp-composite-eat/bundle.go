// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/services/scheme/ocp-composite-eat/internal/eatbundle"
)

const (
	detachedEATBundleTag = eatbundle.Tag
	sha384COSEAlgorithm  = -43
)

var environmentIDPattern = regexp.MustCompile(`^env\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)

type Limits = eatbundle.Limits

func DefaultLimits() Limits {
	return eatbundle.DefaultLimits()
}

type Bundle struct {
	MainToken          []byte
	DetachedClaimsSets map[string][]byte
}

type DetachedDigest struct {
	Algorithm int64
	Value     []byte
}

func ParseBundle(data []byte, limits Limits) (*Bundle, error) {
	envelope, err := eatbundle.Parse(data, limits)
	if err != nil {
		return nil, err
	}
	decMode, err := strictDecMode(limits)
	if err != nil {
		return nil, err
	}
	if err := requireCoreDeterministic(data, decMode); err != nil {
		return nil, fmt.Errorf("bundle encoding: %w", err)
	}

	for environmentID, claimsSet := range envelope.DetachedClaimsSets {
		if err := validateEnvironmentID(environmentID); err != nil {
			return nil, err
		}
		if err := validateDetachedClaimsSet(claimsSet, decMode); err != nil {
			return nil, fmt.Errorf("detached Claims-Set %q: %w", environmentID, err)
		}
	}

	return &Bundle{MainToken: envelope.MainToken, DetachedClaimsSets: envelope.DetachedClaimsSets}, nil
}

func (b *Bundle) VerifyDetachedDigests(expected map[string]DetachedDigest) error {
	if len(expected) != len(b.DetachedClaimsSets) {
		return fmt.Errorf("submods and detached Claims-Set key counts differ: %d != %d", len(expected), len(b.DetachedClaimsSets))
	}

	keys := make([]string, 0, len(expected))
	for environmentID := range expected {
		keys = append(keys, environmentID)
	}
	sort.Strings(keys)

	for _, environmentID := range keys {
		digest := expected[environmentID]
		claimsSet, ok := b.DetachedClaimsSets[environmentID]
		if !ok {
			return fmt.Errorf("submods key %q has no detached Claims-Set", environmentID)
		}
		if digest.Algorithm != sha384COSEAlgorithm {
			return fmt.Errorf("submods[%q] uses algorithm %d, want %d", environmentID, digest.Algorithm, sha384COSEAlgorithm)
		}
		if len(digest.Value) != sha512.Size384 {
			return fmt.Errorf("submods[%q] digest is %d bytes, want %d", environmentID, len(digest.Value), sha512.Size384)
		}
		actual := sha512.Sum384(claimsSet)
		if !bytes.Equal(actual[:], digest.Value) {
			return fmt.Errorf("submods[%q] digest mismatch", environmentID)
		}
	}

	return nil
}

func validateDetachedClaimsSet(data []byte, decMode cbor.DecMode) error {
	if err := requireCoreDeterministic(data, decMode); err != nil {
		return fmt.Errorf("encoding: %w", err)
	}
	return nil
}

func validateEnvironmentID(environmentID string) error {
	if len(environmentID) < 5 || len(environmentID) > 64 || !environmentIDPattern.MatchString(environmentID) {
		return fmt.Errorf("invalid Target Environment Identifier %q", environmentID)
	}
	return nil
}

func strictDecMode(limits Limits) (cbor.DecMode, error) {
	return cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsAllowed,
		MaxArrayElements: limits.MaxSubmodules + 2,
		MaxMapPairs:      limits.MaxSubmodules + 8,
		MaxNestedLevels:  limits.MaxNestedLevels,
	}.DecMode()
}

func requireCoreDeterministic(data []byte, decMode cbor.DecMode) error {
	var value any
	if err := decMode.Unmarshal(data, &value); err != nil {
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
