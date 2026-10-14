// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package handler

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/ear"
	"github.com/veraison/services/vts/appraisal"
)

type endorsementModeTestImplementation struct {
	internal bool
}

func (*endorsementModeTestImplementation) ExtractClaims(
	*appraisal.Evidence,
	[]*comid.KeyTriple,
) (map[string]any, error) {
	return nil, nil
}

func (*endorsementModeTestImplementation) AppraiseClaims(
	map[string]any,
	[]*comid.ValueTriple,
) (*ear.AttestationResult, error) {
	return nil, nil
}

func (o *endorsementModeTestImplementation) UsesExternalEndorsements() bool {
	return !o.internal
}

type defaultEndorsementModeTestImplementation struct{}

func (*defaultEndorsementModeTestImplementation) ExtractClaims(
	*appraisal.Evidence,
	[]*comid.KeyTriple,
) (map[string]any, error) {
	return nil, nil
}

func (*defaultEndorsementModeTestImplementation) AppraiseClaims(
	map[string]any,
	[]*comid.ValueTriple,
) (*ear.AttestationResult, error) {
	return nil, nil
}

func TestSchemeImplementationWrapperEndorsementMode(t *testing.T) {
	descriptor := SchemeDescriptor{
		Name:               "ENDORSEMENT_MODE_TEST",
		VersionMajor:       1,
		CorimProfiles:      []string{"tag:example.com,2026:test"},
		EvidenceMediaTypes: []string{"application/example"},
	}

	defaultWrapper, err := NewSchemeImplementationWrapper(
		descriptor,
		&defaultEndorsementModeTestImplementation{},
	)
	require.NoError(t, err)
	require.True(t, defaultWrapper.UsesExternalEndorsements())

	internalWrapper, err := NewSchemeImplementationWrapper(
		descriptor,
		&endorsementModeTestImplementation{internal: true},
	)
	require.NoError(t, err)
	require.False(t, internalWrapper.UsesExternalEndorsements())
}