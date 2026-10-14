// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSPDMVersionsUseNumericJSONArray(t *testing.T) {
	policy := EvidencePolicy{
		MediaType: "application/spdm-evidence+cbor", SPDMVersions: []uint16{0x10, 0x12},
		BaseHashes: []string{"sha-384"}, BaseAsym: []string{"ecdsa-p384"},
	}
	encoded, err := json.Marshal(policy)
	require.NoError(t, err)
	require.JSONEq(t, `{"mediaType":"application/spdm-evidence+cbor","spdmVersions":[16,18],"baseHashes":["sha-384"],"baseAsym":["ecdsa-p384"]}`, string(encoded))
	var decoded EvidencePolicy
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, policy, decoded)
}

func TestSPDMMeasurementTypePolicyValidation(t *testing.T) {
	policy := EvidencePolicy{
		MediaType: "application/spdm-evidence+cbor", SPDMVersions: []uint16{0x12},
		BaseHashes: []string{"sha-384"}, BaseAsym: []string{"ecdsa-p384"},
	}
	require.NoError(t, policy.Validate())
	policy.SPDMMeasurementTypePolicy = SPDMMeasurementTypePolicyVersionStrict
	require.NoError(t, policy.Validate())
	policy.SPDMMeasurementTypePolicy = SPDMMeasurementTypePolicyKnownTypes
	require.NoError(t, policy.Validate())
	policy.SPDMMeasurementTypePolicy = "ignore"
	require.ErrorContains(t, policy.Validate(), "unsupported SPDM measurement-type policy")
}

func TestPlatformValidationRejectsLabelDriftAndPrivateKey(t *testing.T) {
	registry := &ProfileRegistry{
		CompositeEAT:  ProfileEntry{ID: "composite", Status: "experimental"},
		PlatformCoRIM: ProfileEntry{ID: "platform", Status: "experimental"},
	}
	inventory := PlatformInventory{
		APIVersion: APIVersion, Kind: PlatformKind, ID: "platform-id",
		CompositeEATProfile: "composite", PlatformCoRIMProfile: "platform",
		Validity: Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"},
		Platform: Platform{
			Environment:      Environment{ClassID: "class", Vendor: "vendor", Model: "platform", UEID: "01020304050607"},
			LeadPublicKeyPEM: "PRIVATE KEY", References: []Reference{{KeyType: "string", Key: "fw", Representation: "raw", Value: "01"}},
		},
		Members: []Member{{
			Label: "env.wrong.0", Environment: Environment{ClassID: "member", Vendor: "vendor", Model: "device", UEID: "01020304050608"},
			VendorManifest: "vendor.json",
		}},
	}
	require.ErrorContains(t, inventory.Validate(registry), "private keys")
	inventory.Platform.LeadPublicKeyPEM = "PUBLIC KEY"
	require.ErrorContains(t, inventory.Validate(registry), "does not match model/index")
}

func TestLoadProjectRejectsVendorPathOutsidePackageRoot(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(directory, "outside.json")
	require.NoError(t, os.WriteFile(outside, []byte("{}"), 0o600))
	packageDirectory := filepath.Join(directory, "package")
	require.NoError(t, os.Mkdir(packageDirectory, 0o700))
	inventory := `{
  "apiVersion":"composite-eat.ocp.org/v1alpha1","kind":"PlatformInventory","id":"id",
  "compositeEatProfile":"composite","platformCorimProfile":"platform",
  "validity":{"notBefore":"2026-01-01T00:00:00Z","notAfter":"2027-01-01T00:00:00Z"},
  "platform":{"environment":{"classId":"class","vendor":"vendor","model":"platform","index":0,"ueid":"01020304050607"},"leadPublicKeyPem":"PUBLIC KEY","references":[{"keyType":"string","key":"fw","representation":"raw","value":"01"}]},
  "members":[{"label":"env.device.0","required":true,"environment":{"classId":"device","vendor":"vendor","model":"device","index":0,"ueid":"01020304050608"},"vendorManifest":"../outside.json","collection":{}}]
}`
	platform := filepath.Join(packageDirectory, "platform.json")
	require.NoError(t, os.WriteFile(platform, []byte(inventory), 0o600))
	registry := &ProfileRegistry{CompositeEAT: ProfileEntry{ID: "composite", Status: "experimental"}, PlatformCoRIM: ProfileEntry{ID: "platform", Status: "experimental"}}
	_, err := LoadProject(platform, registry)
	require.ErrorContains(t, err, "escapes package root")
	require.NoError(t, os.Symlink(directory, filepath.Join(packageDirectory, "linked")))
	linked := strings.ReplaceAll(inventory, "../outside.json", "linked/outside.json")
	require.NoError(t, os.WriteFile(platform, []byte(linked), 0o600))
	_, err = LoadProject(platform, registry)
	require.ErrorContains(t, err, "escapes package root")
}

func TestVendorValidationRejectsPlatformLabels(t *testing.T) {
	vendor := VendorManifest{
		APIVersion: APIVersion, Kind: VendorKind, ID: "env.device.0",
		Validity: Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"},
		Model:    "device", EvidenceMediaType: "application/eat+cwt", IdentityPublicKeyPEM: "PUBLIC KEY",
		ReferenceSetID: "active", References: []Reference{{KeyType: "uint", Key: "1", Representation: "raw", Value: "01"}},
	}
	require.ErrorContains(t, vendor.Validate(), "platform labels")
}

func TestReferenceFlagNamesAndProfileURI(t *testing.T) {
	_, err := BuildFlags(map[string]bool{"is-imutable": true})
	require.ErrorContains(t, err, "unsupported measurement flag")
	flags, err := BuildFlags(map[string]bool{"is-debug": false})
	require.NoError(t, err)
	require.NotNil(t, flags.IsDebug)
	require.False(t, *flags.IsDebug)
	require.Error(t, ValidateProfileURI("unqualified-profile"))
	require.NoError(t, ValidateProfileURI("tag:example.com,2026:profile-v1"))
	require.False(t, ValidExplicitLabel("env.Controller.slot"))
	require.True(t, ValidExplicitLabel("env.controller.slota"))
}

func TestComponentInputRejectsUnknownExtensions(t *testing.T) {
	var source ComponentReferenceManifest
	err := decodeJSON([]byte(`{"kind":"ComponentReferenceManifest","vendor-private-data":{"xml":"<private/>"}}`), &source)
	require.ErrorContains(t, err, "unknown field")
}
