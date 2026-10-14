// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/veraison/ear"
)

func TestGenerateDemoArtifacts(t *testing.T) {
	directory := t.TempDir()
	manifest, err := GenerateDemoArtifacts(directory)
	require.NoError(t, err)
	require.Len(t, manifest.Artifacts, 9)

	nonce, err := hex.DecodeString(manifest.Nonce)
	require.NoError(t, err)
	endorsementRoots, err := LoadPEMRoots(filepath.Join(directory, "endorsement-roots.pem"))
	require.NoError(t, err)
	evidenceRoots, err := LoadPEMRoots(filepath.Join(directory, "evidence-roots.pem"))
	require.NoError(t, err)
	snapshot, err := LoadSnapshotFile(filepath.Join(directory, "platform.corim.cose"), endorsementRoots, time.Now())
	require.NoError(t, err)
	engine := Engine{Snapshot: snapshot, EvidenceRoots: evidenceRoots, EnableCaliptraCompatibility: true, Limits: DefaultLimits(), Now: time.Now}

	cases := map[string]Outcome{
		"good.bundle.cbor":               OutcomePass,
		"bad-firmware.bundle.cbor":       OutcomeFail,
		"replay.bundle.cbor":             OutcomeFail,
		"swapped-identities.bundle.cbor": OutcomeFail,
		"missing-member.bundle.cbor":     OutcomeFail,
	}
	for name, expected := range cases {
		data, err := os.ReadFile(filepath.Join(directory, name))
		require.NoError(t, err)
		report, err := engine.Verify(data, nonce)
		require.NoError(t, err, name)
		require.Equal(t, expected, report.Status, name)
		if name == "bad-firmware.bundle.cbor" {
			component := report.Components["env.device.1"]
			require.Equal(t, OutcomePass, component.Dimensions.Identity.Status)
			require.Equal(t, OutcomeFail, component.Dimensions.Measurements.Status)

			handler := NewHandler()
			handler.engine = &engine
			claims, err := reportToMap(report)
			require.NoError(t, err)
			result, err := handler.AppraiseClaims(claims, nil)
			require.NoError(t, err)
			appraisal := result.Submods["env.device.1"]
			require.Equal(t, ear.TrustworthyInstanceClaim, appraisal.TrustVector.InstanceIdentity)
			require.Equal(t, ear.UnrecognizedRuntimeClaim, appraisal.TrustVector.Executables)
		}
	}
}
