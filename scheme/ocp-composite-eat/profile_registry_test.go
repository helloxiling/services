// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

type profileRegistryEntry struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

type profileRegistry struct {
	CompositeEAT          profileRegistryEntry `json:"compositeEat"`
	PlatformCoRIM         profileRegistryEntry `json:"platformCorim"`
	PlatformCoRIMExplicit profileRegistryEntry `json:"platformCorimExplicit"`
	PlatformClass         profileRegistryEntry `json:"platformClass"`
	ComponentClass        profileRegistryEntry `json:"componentClass"`
}

func TestProfileRegistryMatchesVerifierAndGenerator(t *testing.T) {
	encoded, err := os.ReadFile("platformcorim/profiles.json")
	require.NoError(t, err)

	var registry profileRegistry
	require.NoError(t, json.Unmarshal(encoded, &registry))
	require.Equal(t, profileRegistryEntry{
		ID: CompositeEATProfile, Status: "experimental", Version: "1.0.0",
	}, registry.CompositeEAT)
	require.Equal(t, profileRegistryEntry{
		ID: PlatformCoRIMProfile, Status: "experimental", Version: "0.5.0",
	}, registry.PlatformCoRIM)
	require.Equal(t, profileRegistryEntry{
		ID: manifest.ExplicitPlatformProfile, Status: "experimental", Version: "0.5.0",
	}, registry.PlatformCoRIMExplicit)
	require.NotEqual(t, registry.PlatformCoRIM.ID, registry.PlatformCoRIMExplicit.ID)
	require.Equal(t, profileRegistryEntry{ID: manifest.ClassPlatformProfile, Status: "experimental", Version: "0.5.0"}, registry.PlatformClass)
	require.Equal(t, profileRegistryEntry{ID: manifest.ClassComponentProfile, Status: "experimental", Version: "0.5.0"}, registry.ComponentClass)
}
