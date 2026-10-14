// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/veraison/ear"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/compiler"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

func TestGenerateMixedDemoArtifacts(t *testing.T) {
	directory := t.TempDir()
	generated, err := GenerateMixedDemoArtifacts(directory)
	require.NoError(t, err)
	require.Contains(t, generated.Artifacts, "mixed-good.bundle.cbor")
	require.Contains(t, generated.Artifacts, "source-platform.corim.cose")
	require.Contains(t, generated.Artifacts, "source-device.corim.cose")
	require.Contains(t, generated.Artifacts, "source-spdm.corim.cose")

	nonce, err := hex.DecodeString(generated.Nonce)
	require.NoError(t, err)
	endorsementRoots, err := LoadPEMRoots(filepath.Join(directory, "endorsement-roots.pem"))
	require.NoError(t, err)
	evidenceRoots, err := LoadPEMRoots(filepath.Join(directory, "evidence-roots.pem"))
	require.NoError(t, err)
	snapshot, err := LoadSnapshotFile(filepath.Join(directory, "platform.corim.cose"), endorsementRoots, time.Now())
	require.NoError(t, err)
	engine := Engine{
		Snapshot: snapshot, EvidenceRoots: evidenceRoots, EnableNativeSPDM: true,
		EnableCaliptraCompatibility: true, Limits: DefaultLimits(), Now: time.Now,
	}

	tests := []struct {
		name   string
		status Outcome
		check  func(*testing.T, *Report)
	}{
		{name: "mixed-good.bundle.cbor", status: OutcomePass, check: func(t *testing.T, report *Report) {
			require.Equal(t, OutcomePass, report.Components["env.device.0"].Status)
			require.Equal(t, OutcomePass, report.Components["env.spdm.0"].Status)
		}},
		{name: "mixed-spdm-bad-signature.bundle.cbor", status: OutcomeFail, check: func(t *testing.T, report *Report) {
			require.Equal(t, OutcomeFail, report.Components["env.spdm.0"].Dimensions.EvidenceProtection.Status)
		}},
		{name: "mixed-spdm-replay.bundle.cbor", status: OutcomeFail, check: func(t *testing.T, report *Report) {
			component := report.Components["env.spdm.0"]
			require.Equal(t, OutcomePass, component.Dimensions.EvidenceProtection.Status)
			require.Equal(t, OutcomeFail, component.Dimensions.Freshness.Status)
			require.Equal(t, OutcomePass, component.Dimensions.Identity.Status)
			require.Equal(t, OutcomeIndeterminate, component.Dimensions.Measurements.Status)
		}},
		{name: "mixed-spdm-bad-measurement.bundle.cbor", status: OutcomeFail, check: func(t *testing.T, report *Report) {
			component := report.Components["env.spdm.0"]
			require.Equal(t, OutcomePass, component.Dimensions.Identity.Status)
			require.Equal(t, OutcomeFail, component.Dimensions.Measurements.Status)
		}},
		{name: "mixed-unsupported.bundle.cbor", status: OutcomeFail, check: func(t *testing.T, report *Report) {
			require.Equal(t, OutcomeUnsupported, report.Components["env.spdm.0"].Status)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle, err := os.ReadFile(filepath.Join(directory, test.name))
			require.NoError(t, err)
			report, err := engine.Verify(bundle, nonce)
			require.NoError(t, err)
			require.Equal(t, test.status, report.Status)
			claims, err := reportToMap(report)
			require.NoError(t, err)
			result, err := NewHandler().AppraiseClaims(claims, nil)
			require.NoError(t, err)
			if test.status == OutcomePass {
				require.Equal(t, ear.TrustTierAffirming, *result.Submods[SchemeName].Status)
			} else {
				require.NotEqual(t, ear.TrustTierAffirming, *result.Submods[SchemeName].Status)
			}
			if test.check != nil {
				test.check(t, report)
			}
		})
	}

	registry := &manifest.ProfileRegistry{
		CompositeEAT:  manifest.ProfileEntry{ID: CompositeEATProfile, Status: "experimental", Version: "1.0.0"},
		PlatformCoRIM: manifest.ProfileEntry{ID: PlatformCoRIMProfile, Status: "experimental", Version: "0.5.0"},
	}
	project, err := manifest.LoadProject(filepath.Join(directory, "source/platform.json"), registry)
	require.NoError(t, err)
	plan := compiler.BuildCollectionPlan(project)
	planLabels := make([]string, 0, len(plan.Members))
	snapshotLabels := make([]string, 0, len(snapshot.Members))
	for _, member := range plan.Members {
		planLabels = append(planLabels, member.Label)
	}
	for label := range snapshot.Members {
		snapshotLabels = append(snapshotLabels, label)
	}
	sort.Strings(planLabels)
	sort.Strings(snapshotLabels)
	require.Equal(t, planLabels, snapshotLabels)
	provenanceData, err := os.ReadFile(filepath.Join(directory, "snapshot-provenance.json"))
	require.NoError(t, err)
	var provenance manifest.SnapshotProvenance
	require.NoError(t, json.Unmarshal(provenanceData, &provenance))
	require.Contains(t, provenance.SourceDigests, "authenticated:platform")
	require.Contains(t, provenance.SourceDigests, "authenticated:"+project.Members[0].Vendor.ID)

	err = filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		require.False(t, strings.Contains(string(data), "PRIVATE KEY"), path)
		return nil
	})
	require.NoError(t, err)
}
