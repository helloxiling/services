// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

func TestLoadSnapshotAndAuthorizeLead(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	require.Equal(t, PlatformCoRIMProfile, snapshot.Profile)
	require.Contains(t, snapshot.Members, "env.device.0")
	require.NoError(t, snapshot.AuthorizeLead(&LeadClaims{
		UEID: fixture.leadUEID,
		Leaf: fixture.leadCertificate,
	}))
}

func TestLoadSnapshotRejectsUntrustedSigner(t *testing.T) {
	fixture := newSnapshotFixture(t)
	_, err := LoadSnapshot(fixture.encoded, x509.NewCertPool(), fixture.now)
	require.ErrorContains(t, err, "validate Platform CoRIM signer")
}

func TestLoadSnapshotRejectsExpiredManifest(t *testing.T) {
	fixture := newSnapshotFixture(t)
	_, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now.Add(48*time.Hour))
	require.ErrorContains(t, err, "expired")
}

func TestExplicitMembershipRejectsAmbiguity(t *testing.T) {
	environment := comid.Environment{Class: comid.NewClassBytes([]byte("component")).SetModel("controller").SetIndex(2)}
	component := comid.NewComid().SetTagIdentity("tag:example.com,2026:bindings", 0)
	component.Triples.AddDomainMembership(&comid.DomainMembershipTriple{DomainID: environment, Members: []comid.Environment{environment}})
	policy := &manifest.PolicyExtension{Binding: manifest.ExplicitBinding, Members: map[string]manifest.MemberPolicy{"env.controller.slota": {Environment: &environment}}}
	_, members, err := collectMembership([]*comid.Comid{component}, policy)
	require.NoError(t, err)
	require.Contains(t, members, "env.controller.slota")
	policy.Members["env.controller.slotb"] = policy.Members["env.controller.slota"]
	_, _, err = collectMembership([]*comid.Comid{component}, policy)
	require.ErrorContains(t, err, "ambiguous")
	delete(policy.Members, "env.controller.slotb")
	policy.Members["env.controller.slota"] = manifest.MemberPolicy{}
	_, _, err = collectMembership([]*comid.Comid{component}, policy)
	require.ErrorContains(t, err, "no signed label")
	require.NoError(t, manifest.RegisterPolicy(component, policy))
	_, err = snapshotContract([]*comid.Comid{component}, PlatformCoRIMProfile)
	require.ErrorContains(t, err, "legacy profile")
	_, err = snapshotContract([]*comid.Comid{component}, manifest.ExplicitPlatformProfile)
	require.ErrorContains(t, err, "incomplete")
}

func TestSnapshotProfileMustMatchAuthenticatedLead(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	_, err = (SnapshotProvider{Snapshot: snapshot}).Resolve(context.Background(), EndorsementRequest{Profile: "tag:example.com,2026:other", LeadUEID: fixture.leadUEID, LeadPublicKey: fixture.leadCertificate.PublicKey, VerificationTime: fixture.now})
	require.ErrorContains(t, err, "profile")
}

type snapshotFixture struct {
	encoded          []byte
	endorsementRoots *x509.CertPool
	now              time.Time
	leadUEID         []byte
	leadCertificate  *x509.Certificate
	leadKey          *ecdsa.PrivateKey
	leadRoots        *x509.CertPool
	deviceUEID       []byte
	deviceKey        *ecdsa.PrivateKey
}

func newSnapshotFixture(t *testing.T) snapshotFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	endorsementRootKey, endorsementRootDER, endorsementRoot := makeCertificate(t, nil, nil, true, "Endorsement Root", now)
	endorsementKey, endorsementDER, _ := makeCertificate(t, endorsementRoot, endorsementRootKey, false, "Platform Endorser", now)
	leadKey, _, leadCertificate := makeCertificate(t, nil, nil, true, "Lead Attester", now)
	deviceKey, _, _ := makeCertificate(t, nil, nil, true, "Device Attester", now)

	leadUEID := append([]byte{1}, make([]byte, 16)...)
	deviceUEID := append([]byte{1}, make([]byte, 16)...)
	for index := 1; index < len(leadUEID); index++ {
		leadUEID[index] = byte(index)
		deviceUEID[index] = byte(index + 32)
	}
	platform := comid.Environment{
		Class:    comid.NewClassBytes([]byte("demo-platform")).SetModel("platform").SetIndex(0),
		Instance: comid.MustNewUEIDInstance(leadUEID),
	}
	device := comid.Environment{
		Class:    comid.NewClassBytes([]byte("demo-device")).SetModel("device").SetIndex(0),
		Instance: comid.MustNewUEIDInstance(deviceUEID),
	}

	component := comid.NewComid().SetTagIdentity("tag:example.com,2026:demo-platform", 0)
	require.NoError(t, manifest.RegisterPolicy(component, &manifest.PolicyExtension{Binding: "demo-model-index-v1", Members: map[string]manifest.MemberPolicy{
		"env.device.0": {Required: true, ReferenceSet: "device-v1", Evidence: manifest.EvidencePolicy{MediaType: eatContentType, DeviceMode: "caliptra"}},
	}}))
	component.Triples.AddDomainMembership(&comid.DomainMembershipTriple{
		DomainID: platform, Members: []comid.Environment{device},
	})
	component.AddAttestVerifKey(&comid.KeyTriple{
		Environment: platform,
		VerifKeys:   *comid.NewCryptoKeys().Add(comid.MustNewPKIXBase64Key(publicKeyPEM(t, &leadKey.PublicKey))),
	})
	component.AddAttestVerifKey(&comid.KeyTriple{
		Environment: device,
		VerifKeys:   *comid.NewCryptoKeys().Add(comid.MustNewPKIXBase64Key(publicKeyPEM(t, &deviceKey.PublicKey))),
	})
	component.AddReferenceValue(referenceValue(platform, "lead.firmware", 0x11))
	component.AddReferenceValue(referenceValue(device, "device.firmware", 0x22))

	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(24 * time.Hour)
	unsigned := corim.NewUnsignedCorim().
		SetID("tag:example.com,2026:demo-platform-corim").
		SetProfile(PlatformCoRIMProfile).
		SetRimValidity(notAfter, &notBefore).
		AddComid(component)
	require.NotNil(t, unsigned)

	signer, err := cose.NewSigner(cose.AlgorithmES384, endorsementKey)
	require.NoError(t, err)
	signed := corim.NewSignedCorim()
	signed.UnsignedCorim = *unsigned
	signed.Meta = *corim.NewMeta().SetSigner("Demo Platform Endorser", nil).SetValidity(notAfter, &notBefore)
	require.NoError(t, signed.AddSigningCert(endorsementDER))
	require.NoError(t, signed.AddIntermediateCerts(endorsementRootDER))
	encoded, err := signed.Sign(signer)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(endorsementRoot)
	leadRoots := x509.NewCertPool()
	leadRoots.AddCert(leadCertificate)
	return snapshotFixture{
		encoded: encoded, endorsementRoots: roots, now: now,
		leadUEID: leadUEID, leadCertificate: leadCertificate,
		leadKey: leadKey, leadRoots: leadRoots,
		deviceUEID: deviceUEID, deviceKey: deviceKey,
	}
}

func referenceValue(environment comid.Environment, key string, fill byte) *comid.ValueTriple {
	digest := make([]byte, 48)
	for index := range digest {
		digest[index] = fill
	}
	return &comid.ValueTriple{
		Environment: environment,
		Measurements: *comid.NewMeasurements().Add(
			comid.MustNewMeasurement(key, comid.StringType).AddDigest(comid.Sha384, digest),
		),
	}
}

func publicKeyPEM(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
