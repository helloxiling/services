// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package compiler_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/services/scheme/ocp-composite-eat"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/compiler"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

func TestPortableExamplesShareVendorAndLabelsAcrossOutputs(t *testing.T) {
	registry, err := manifest.LoadRegistry("../profiles.json")
	require.NoError(t, err)
	vendorIDs := make([]string, 0, 2)
	for _, board := range []string{"platform-a", "platform-b"} {
		project, err := manifest.LoadProjectAtRoot(filepath.Join("../../example/class/manifests", board, "platform.json"), registry, "../../example/class/manifests")
		require.NoError(t, err)
		require.Len(t, project.Members, 1)
		vendorIDs = append(vendorIDs, project.Members[0].Vendor.ID)

		unsigned, err := compiler.BuildPlatform(project, true)
		require.NoError(t, err)
		encoded, err := unsigned.ToCBOR()
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "/redfish/")
		require.NotContains(t, string(encoded), "3-003a")

		coRIMLabels := labelsFromCoRIM(t, unsigned)
		plan := compiler.BuildCollectionPlan(project)
		encodedPlan, err := compiler.MarshalCollectionPlan(project)
		require.NoError(t, err)
		var document map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(encodedPlan, &document))
		require.Contains(t, document, "environments")
		require.NotContains(t, document, "members")
		var mappings []map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(document["environments"], &mappings))
		require.Contains(t, mappings[0], "env")
		require.Contains(t, mappings[0], "match")
		planLabels := make([]string, 0, len(plan.Members))
		for _, member := range plan.Members {
			planLabels = append(planLabels, member.Label)
		}
		require.Equal(t, compiler.Labels(project), coRIMLabels)
		require.Equal(t, compiler.Labels(project), planLabels)
	}
	require.Equal(t, vendorIDs[0], vendorIDs[1])
}

func TestCocliExportPreservesCoMIDBytes(t *testing.T) {
	var source manifest.PlatformClassManifest
	data, err := os.ReadFile("../../example/class/manifests/composite-eat-class/platform-class.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &source))
	unsigned, err := compiler.BuildPlatformClass(source)
	require.NoError(t, err)
	expected, err := unsigned.ToCBOR()
	require.NoError(t, err)
	files, err := compiler.ExportCocliInputs(unsigned)
	require.NoError(t, err)
	var template corim.UnsignedCorim
	require.NoError(t, json.Unmarshal(files["corim-template.json"], &template))
	require.Empty(t, template.Tags)
	for index, tag := range unsigned.Tags {
		content := files[fmt.Sprintf("comid-%03d.cbor", index)]
		require.Equal(t, tag.Content, content)
		template.Tags = append(template.Tags, corim.Tag{Number: corim.ComidTag, Content: content})
	}
	actual, err := template.ToCBOR()
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	files["comid-000.cbor"][0] ^= 1
	after, err := unsigned.ToCBOR()
	require.NoError(t, err)
	require.Equal(t, expected, after)
}

func TestSignedDemoSnapshotLoadsThroughVerifierContract(t *testing.T) {
	registry, err := manifest.LoadRegistry("../profiles.json")
	require.NoError(t, err)
	project, err := manifest.LoadProjectAtRoot("../../example/class/manifests/platform-a/platform.json", registry, "../../example/class/manifests")
	require.NoError(t, err)
	unsigned, err := compiler.BuildPlatform(project, true)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	now := time.Date(2026, time.September, 16, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo Snapshot Authority"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	signed, err := compiler.SignDemoSnapshot(unsigned,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		"Demo Snapshot Authority")
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(certificateDER)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	snapshot, err := ocp_composite_eat.LoadSnapshot(signed, roots, now)
	require.NoError(t, err)
	require.Contains(t, snapshot.Members, "env.tpm.0")
}

func labelsFromCoRIM(t *testing.T, unsigned *corim.UnsignedCorim) []string {
	t.Helper()
	var labels []string
	sequence, sequenceErr := unsigned.IterComids()
	for item := range sequence {
		if item.Triples.DomainMemberships == nil {
			continue
		}
		for _, triple := range *item.Triples.DomainMemberships {
			for _, environment := range triple.Members {
				labels = append(labels, "env."+*environment.Class.Model+"."+itoa(*environment.Class.Index))
			}
		}
	}
	require.NoError(t, sequenceErr())
	sort.Strings(labels)
	return labels
}

func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

func TestAuthenticatedSourcesRejectConflictsAndPreserveExpiry(t *testing.T) {
	registry, err := manifest.LoadRegistry("../profiles.json")
	require.NoError(t, err)
	project, err := manifest.LoadProjectAtRoot("../../example/class/manifests/platform-a/platform.json", registry, "../../example/class/manifests")
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	project.Inventory.Validity = manifest.Validity{NotBefore: now.Add(-time.Hour).Format(time.RFC3339), NotAfter: now.Add(24 * time.Hour).Format(time.RFC3339)}
	project.Members[0].Vendor.Validity = manifest.Validity{NotBefore: now.Add(-time.Hour).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339)}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	fingerprint := sha256.Sum256(der)
	scopes := map[string]string{"platform": hex.EncodeToString(fingerprint[:]), project.Members[0].Vendor.ID: hex.EncodeToString(fingerprint[:])}
	sign := func(unsigned *corim.UnsignedCorim) []byte {
		data, err := compiler.SignDemoSnapshot(unsigned, privatePEM, certPEM, "review")
		require.NoError(t, err)
		return data
	}
	vendor, err := compiler.BuildVendor(project.Members[0].Vendor)
	require.NoError(t, err)
	vendors := map[string][]byte{project.Members[0].Vendor.ID: sign(vendor)}
	build := func(authorizations map[string]string) ([]byte, error) {
		platform, err := compiler.BuildPlatform(project, false)
		require.NoError(t, err)
		data, _, err := compiler.CompileAuthenticatedDemoSnapshot(project, sign(platform), vendors, roots, now, privatePEM, certPEM, "snapshot", authorizations)
		return data, err
	}
	_, err = build(nil)
	require.ErrorContains(t, err, "not authorized")
	snapshot, err := build(scopes)
	require.NoError(t, err)
	_, err = ocp_composite_eat.LoadSnapshot(snapshot, roots, now.Add(2*time.Hour))
	require.ErrorContains(t, err, "expired")
	second := project.Members[0]
	second.Member.Label = "env.tpm.1"
	second.Member.Environment.Index = 1
	project.Members = append(project.Members, second)
	project.Inventory.Members = append(project.Inventory.Members, second.Member)
	_, err = build(scopes)
	require.NoError(t, err)
	project.Members[1].Vendor.ReferenceSetID = "unauthorized-release"
	_, err = build(scopes)
	require.ErrorContains(t, err, "drift")
	project.Members[1].Vendor = second.Vendor
	project.Members[1].Vendor.References = []manifest.Reference{{KeyType: "uint", Key: "1", Representation: "raw", Value: "deadbeef"}}
	_, err = build(scopes)
	require.ErrorContains(t, err, "drift")
	project.Members[1].Vendor = second.Vendor
	project.Members[1].Vendor.IdentityPublicKeyPEM = project.Inventory.Platform.LeadPublicKeyPEM
	_, err = build(scopes)
	require.ErrorContains(t, err, "drift")
	project.Members[1].Vendor = second.Vendor
	project.Members[1].Vendor.EvidenceMediaType = "application/eat+cwt"
	_, err = build(scopes)
	require.ErrorContains(t, err, "drift")
}

func TestDualComponentSnapshot(t *testing.T) {
	registry, err := manifest.LoadRegistry("../profiles.json")
	require.NoError(t, err)
	project, err := manifest.LoadProject("testdata/dual-component/platform.json", registry)
	require.NoError(t, err)
	require.Len(t, project.Members, 2)
	expectedLabels := []string{"env.controller.0", "env.controller.1"}
	require.Equal(t, expectedLabels, compiler.Labels(project))
	require.NotEqual(t, project.Members[0].Member.Environment.UEID, project.Members[1].Member.Environment.UEID)
	require.NotEqual(t, project.Members[0].Vendor.ID, project.Members[1].Vendor.ID)
	require.NotEqual(t, project.Members[0].Vendor.IdentityPublicKeyPEM, project.Members[1].Vendor.IdentityPublicKeyPEM)
	require.Equal(t, project.Members[0].Vendor.References, project.Members[1].Vendor.References)
	for _, member := range project.Members {
		require.True(t, member.Member.Required)
		require.Equal(t, []uint16{0x12}, member.Vendor.Policy().Evidence.SPDMVersions)
		vendor, err := compiler.BuildVendor(member.Vendor)
		require.NoError(t, err)
		_, err = vendor.ToCBOR()
		require.NoError(t, err)
	}
	platform, err := compiler.BuildPlatform(project, false)
	require.NoError(t, err)
	require.Equal(t, expectedLabels, labelsFromCoRIM(t, platform))
	_, err = platform.ToCBOR()
	require.NoError(t, err)
	encodedPlan, err := compiler.MarshalCollectionPlan(project)
	require.NoError(t, err)
	var plan struct {
		Environments []struct {
			Label string `json:"env"`
			Match struct {
				EID uint8 `json:"mctpEid"`
			} `json:"match"`
		} `json:"environments"`
	}
	require.NoError(t, json.Unmarshal(encodedPlan, &plan))
	require.Len(t, plan.Environments, 2)
	for index, entry := range plan.Environments {
		require.Equal(t, expectedLabels[index], entry.Label)
		require.Equal(t, uint8(12+index), entry.Match.EID)
	}

	now := time.Date(2026, time.September, 17, 12, 0, 0, 0, time.UTC)
	newAuthority := func(name string, serial int64) ([]byte, []byte, *x509.Certificate, string) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)
		certificate, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		fingerprint := sha256.Sum256(der)
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate, hex.EncodeToString(fingerprint[:])
	}
	platformKey, platformPEM, platformCert, platformFingerprint := newAuthority("Synthetic Platform Issuer", 1)
	vendorKey, vendorPEM, vendorCert, vendorFingerprint := newAuthority("Synthetic Component Endorser", 2)
	snapshotKey, snapshotPEM, snapshotCert, _ := newAuthority("Synthetic Snapshot Authority", 3)
	signedPlatform, err := compiler.SignDemoSnapshot(platform, platformKey, platformPEM, "Synthetic Platform Issuer")
	require.NoError(t, err)
	signedVendors := make(map[string][]byte)
	scopes := map[string]string{"platform": platformFingerprint}
	for _, member := range project.Members {
		vendor, err := compiler.BuildVendor(member.Vendor)
		require.NoError(t, err)
		signedVendors[member.Vendor.ID], err = compiler.SignDemoSnapshot(vendor, vendorKey, vendorPEM, "Synthetic Component Endorser")
		require.NoError(t, err)
		scopes[member.Vendor.ID] = vendorFingerprint
	}
	sourceRoots := x509.NewCertPool()
	sourceRoots.AddCert(platformCert)
	sourceRoots.AddCert(vendorCert)
	encodedSnapshot, provenance, err := compiler.CompileAuthenticatedDemoSnapshot(
		project, signedPlatform, signedVendors, sourceRoots, now, snapshotKey, snapshotPEM, "Synthetic Snapshot Authority", scopes)
	require.NoError(t, err)
	require.Len(t, provenance, 3)
	snapshotRoots := x509.NewCertPool()
	snapshotRoots.AddCert(snapshotCert)
	snapshot, err := ocp_composite_eat.LoadSnapshot(encodedSnapshot, snapshotRoots, now)
	require.NoError(t, err)
	require.Len(t, snapshot.Members, 2)
	for _, label := range expectedLabels {
		require.Contains(t, snapshot.Members, label)
		require.Len(t, snapshot.Members[label].IdentityKeys, 1)
		require.True(t, snapshot.Members[label].Policy.Required)
		require.Equal(t, "test-controller-release-1", snapshot.Members[label].Policy.ReferenceSet)
	}
	firstKey, err := x509.MarshalPKIXPublicKey(snapshot.Members[expectedLabels[0]].IdentityKeys[0])
	require.NoError(t, err)
	secondKey, err := x509.MarshalPKIXPublicKey(snapshot.Members[expectedLabels[1]].IdentityKeys[0])
	require.NoError(t, err)
	require.NotEqual(t, firstKey, secondKey)

	scopes[project.Members[0].Vendor.ID] = platformFingerprint
	_, _, err = compiler.CompileAuthenticatedDemoSnapshot(
		project, signedPlatform, signedVendors, sourceRoots, now, snapshotKey, snapshotPEM, "Synthetic Snapshot Authority", scopes)
	require.ErrorContains(t, err, "not authorized")
}

func TestExplicitEnvironmentSnapshot(t *testing.T) {
	registry, err := manifest.LoadRegistry("../profiles.json")
	require.NoError(t, err)
	project, err := manifest.LoadProject("testdata/dual-component/platform.json", registry)
	require.NoError(t, err)
	project.Inventory.PlatformCoRIMProfile = manifest.ExplicitPlatformProfile
	project.Inventory.Platform.References = nil
	measured := comid.Environment{Class: comid.NewClassBytes([]byte("boot-state")).SetModel("boot")}
	project.Inventory.Platform.MeasurementEnvironments = []manifest.ReferenceEnvironment{{Environment: measured, References: []manifest.Reference{{KeyType: "string", Key: "boot-register", Representation: "digest", Algorithm: "sha-512", Value: hex.EncodeToString(make([]byte, 64)), Flags: map[string]bool{"is-immutable": true, "is-debug": false}}}}}
	for index := range project.Members {
		project.Members[index].Member.Label = "env.controller.slot" + itoa(uint64(index))
		project.Members[index].Member.Environment.UEID = ""
		project.Inventory.Members[index] = project.Members[index].Member
	}
	require.NoError(t, project.Inventory.Validate(registry))
	unsigned, err := compiler.BuildPlatform(project, false)
	require.NoError(t, err)
	now := time.Date(2026, time.September, 17, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(8), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	privateDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	sign := func(unsigned *corim.UnsignedCorim) []byte {
		encoded, err := compiler.SignDemoSnapshot(unsigned, privatePEM, certificatePEM, "Synthetic Explicit Authority")
		require.NoError(t, err)
		return encoded
	}
	signedPlatform := sign(unsigned)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	fingerprint := sha256.Sum256(der)
	scopes := map[string]string{"platform": hex.EncodeToString(fingerprint[:])}
	vendors := map[string][]byte{}
	for _, member := range project.Members {
		vendor, err := compiler.BuildVendor(member.Vendor)
		require.NoError(t, err)
		vendors[member.Vendor.ID] = sign(vendor)
		scopes[member.Vendor.ID] = scopes["platform"]
	}
	encoded, _, err := compiler.CompileAuthenticatedDemoSnapshot(project, signedPlatform, vendors, roots, now, privatePEM, certificatePEM, "Synthetic Explicit Authority", scopes)
	require.NoError(t, err)
	snapshot, err := ocp_composite_eat.LoadSnapshot(encoded, roots, now)
	require.NoError(t, err)
	require.Equal(t, manifest.ExplicitPlatformProfile, snapshot.Profile)
	require.Equal(t, project.Inventory.CompositeEATProfile, snapshot.CompositeEATProfile)
	require.Contains(t, snapshot.Members, "env.controller.slot0")
	require.Len(t, snapshot.LeadReferenceValues, 1)
	require.Equal(t, measured, snapshot.LeadReferenceValues[0].Environment)
	require.True(t, ocp_composite_eat.AppraiseMeasurements(snapshot.LeadReferenceValues, snapshot.LeadReferenceValues).Passed)
	project.Members[0].Member.Label = "env.controller.substituted"
	_, _, err = compiler.CompileAuthenticatedDemoSnapshot(project, signedPlatform, vendors, roots, now, privatePEM, certificatePEM, "Synthetic Explicit Authority", scopes)
	require.ErrorContains(t, err, "platform source drift")
	project.Inventory.PlatformCoRIMProfile = registry.PlatformCoRIM.ID
	require.Error(t, project.Inventory.Validate(registry))
}
