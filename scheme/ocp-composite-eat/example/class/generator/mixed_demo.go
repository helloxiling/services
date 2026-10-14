// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/compiler"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

type classDemo struct {
	Input            ClassProviderInput
	SourceRoots      *x509.CertPool
	SourceRootsPEM   []byte
	EvidenceRoots    *x509.CertPool
	EvidenceRootsPEM []byte
	Bundles          map[string][]byte
	Nonce            []byte
	PlatformSigner   *demoKeyPair
	ComponentSigner  *demoKeyPair
}

func GenerateClassDemoArtifacts(outputDirectory string) (*DemoManifest, error) {
	now := time.Now().UTC().Truncate(time.Second)
	demo, err := newClassDemo(now)
	if err != nil {
		return nil, err
	}
	return writeClassDemoArtifacts(outputDirectory, demo, now)
}

func GenerateClassDemoArtifactsWithCocli(outputDirectory, cocliPath string) (*DemoManifest, error) {
	now := time.Now().UTC().Truncate(time.Second)
	demo, err := newClassDemo(now)
	if err != nil {
		return nil, err
	}
	platform, err := compiler.BuildPlatformClass(demo.Input.Platform)
	if err != nil {
		return nil, err
	}
	demo.Input.SignedPlatform, err = signClassSourceWithCocli(cocliPath, platform, demo.PlatformSigner)
	if err != nil {
		return nil, err
	}
	for id, source := range demo.Input.Components {
		component, err := compiler.BuildComponentClass(source.Manifest)
		if err != nil {
			return nil, err
		}
		source.SignedCoRIM, err = signClassSourceWithCocli(cocliPath, component, demo.ComponentSigner)
		if err != nil {
			return nil, err
		}
		demo.Input.Components[id] = source
	}
	return writeClassDemoArtifacts(outputDirectory, demo, now)
}

func writeClassDemoArtifacts(outputDirectory string, demo *classDemo, now time.Time) (*DemoManifest, error) {
	files := map[string][]byte{"platform-class.cose": demo.Input.SignedPlatform, "source-roots.pem": demo.SourceRootsPEM, "evidence-roots.pem": demo.EvidenceRootsPEM, "nonce.hex": []byte(hex.EncodeToString(demo.Nonce) + "\n")}
	encode := func(name string, value any) error {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		files[name] = append(data, '\n')
		return nil
	}
	if err := encode("platform-class.json", demo.Input.Platform); err != nil {
		return nil, err
	}
	if err := encode("enrollments.json", demo.Input.Enrollments); err != nil {
		return nil, err
	}
	config := ClassPackage{APIVersion: manifest.APIVersion, Kind: "ClassEndorsementPackage", Platform: ClassSourceFiles{Manifest: "platform-class.json", CoRIM: "platform-class.cose", SHA256: fmt.Sprintf("%x", sha256.Sum256(demo.Input.SignedPlatform))}, Enrollments: "enrollments.json", EnrollmentSHA256: fmt.Sprintf("%x", sha256.Sum256(files["enrollments.json"])), SignerScopes: demo.Input.SignerScopes}
	for _, source := range demo.Input.Components {
		if err := encode("component-class.json", source.Manifest); err != nil {
			return nil, err
		}
		files["component-class.cose"] = source.SignedCoRIM
		config.Components = append(config.Components, ClassSourceFiles{Manifest: "component-class.json", CoRIM: "component-class.cose", SHA256: fmt.Sprintf("%x", sha256.Sum256(source.SignedCoRIM))})
	}
	if err := encode("class-package.json", config); err != nil {
		return nil, err
	}
	for name, bundle := range demo.Bundles {
		files[name+".bundle.cbor"] = bundle
	}
	result := &DemoManifest{GeneratedAt: now.Format(time.RFC3339), Profile: manifest.ClassPlatformProfile, Nonce: hex.EncodeToString(demo.Nonce), Artifacts: map[string]string{}}
	for name, data := range files {
		if err := writeDemoFile(outputDirectory, name, data); err != nil {
			return nil, err
		}
		result.Artifacts[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeDemoFile(outputDirectory, "manifest.json", append(encoded, '\n')); err != nil {
		return nil, err
	}
	return result, nil
}

func signClassSourceWithCocli(cocliPath string, unsigned *corim.UnsignedCorim, issuer *demoKeyPair) ([]byte, error) {
	if cocliPath == "" || issuer == nil {
		return nil, errors.New("cocli executable and demo issuer are required")
	}
	directory, err := os.MkdirTemp("", "composite-eat-cocli-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	files, err := compiler.ExportCocliInputs(unsigned)
	if err != nil {
		return nil, err
	}
	var comids []string
	for name, data := range files {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}
		if filepath.Ext(name) == ".cbor" {
			comids = append(comids, path)
		}
	}
	sort.Strings(comids)
	unsignedPath := filepath.Join(directory, "unsigned.cbor")
	arguments := make([]string, 0, 6+2*len(comids))
	arguments = append(arguments, "corim", "create", "--template", filepath.Join(directory, "corim-template.json"), "--output", unsignedPath)
	for _, path := range comids {
		arguments = append(arguments, "--comid", path)
	}
	if output, err := exec.Command(cocliPath, arguments...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cocli create: %w: %s", err, output)
	}
	encode := func(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
	publicKey, err := issuer.Key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	privateKey, err := issuer.Key.Bytes()
	if err != nil {
		return nil, err
	}
	jwk := map[string]string{
		"kty": "EC", "crv": "P-384", "alg": "ES384",
		"x": encode(publicKey[1:49]),
		"y": encode(publicKey[49:]),
		"d": encode(privateKey),
	}
	keyData, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(directory, "issuer.jwk")
	certPath := filepath.Join(directory, "issuer.der")
	metaPath := filepath.Join(directory, "meta.json")
	if err := os.WriteFile(keyPath, keyData, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, issuer.DER, 0o600); err != nil {
		return nil, err
	}
	meta := corim.NewMeta().SetSigner(issuer.Cert.Subject.CommonName, nil).SetValidity(unsigned.RimValidity.NotAfter, unsigned.RimValidity.NotBefore)
	metaData, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(metaPath, metaData, 0o600); err != nil {
		return nil, err
	}
	signedPath := filepath.Join(directory, "signed.cose")
	if output, err := exec.Command(cocliPath, "corim", "sign", "--file", unsignedPath, "--key", keyPath, "--cert", certPath, "--meta", metaPath, "--output", signedPath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cocli sign: %w: %s", err, output)
	}
	return os.ReadFile(signedPath)
}

func newClassDemo(now time.Time) (*classDemo, error) {
	platformSigner, err := demoMakeCertificate(nil, nil, true, "Synthetic Platform Class Issuer", now)
	if err != nil {
		return nil, err
	}
	componentSigner, err := demoMakeCertificate(nil, nil, true, "Synthetic Component Class Issuer", now)
	if err != nil {
		return nil, err
	}
	evidenceRoot, err := demoMakeCertificate(nil, nil, true, "Synthetic Class Demo Evidence Root", now)
	if err != nil {
		return nil, err
	}
	result := &classDemo{SourceRoots: x509.NewCertPool(), EvidenceRoots: x509.NewCertPool(), Bundles: map[string][]byte{}, Nonce: make([]byte, 32), PlatformSigner: platformSigner, ComponentSigner: componentSigner}
	if _, err := rand.Read(result.Nonce); err != nil {
		return nil, err
	}
	for _, signer := range []*demoKeyPair{platformSigner, componentSigner} {
		result.SourceRoots.AddCert(signer.Cert)
		result.SourceRootsPEM = append(result.SourceRootsPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.DER})...)
	}
	result.EvidenceRoots.AddCert(evidenceRoot.Cert)
	result.EvidenceRootsPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: evidenceRoot.DER})
	validity := manifest.Validity{NotBefore: now.Add(-time.Hour).Format(time.RFC3339), NotAfter: now.Add(24 * time.Hour).Format(time.RFC3339)}
	component := manifest.ComponentReferenceManifest{APIVersion: manifest.APIVersion, Kind: "ComponentReferenceManifest", ID: "tag:example.com,2026:shared-controller-release", ComponentClass: "controller-generation-2", Validity: validity, ReferenceSetID: "controller-release-4", Environment: comid.Environment{Class: comid.NewClassBytes([]byte("controller-generation-2")).SetVendor("Example").SetModel("controller")}, Evidence: manifest.EvidencePolicy{MediaType: spdmEvidenceMediaType, SPDMVersions: []uint16{0x12}, BaseHashes: []string{"sha-384"}, BaseAsym: []string{"ecdsa-p384"}}, References: []manifest.Reference{{KeyType: "uint", Key: "1", Representation: "raw", Value: hex.EncodeToString([]byte("approved-controller-release-4"))}}}
	first := manifest.ClassMember{Label: "env.controller.0", Required: true, ComponentID: component.ID, ComponentClass: component.ComponentClass, ReferenceSetID: component.ReferenceSetID}
	second := first
	second.Label = "env.controller.1"
	platform := manifest.PlatformClassManifest{APIVersion: manifest.APIVersion, Kind: "PlatformClassManifest", ID: "tag:example.com,2026:shared-blade-family", Revision: "revision-3", CompositeEATProfile: CompositeEATProfile, Validity: validity, Environment: comid.Environment{Class: comid.NewClassBytes([]byte("blade-family")).SetModel("platform")}, LeadClass: "platform-root-generation-2", LeadMeasurements: []manifest.ReferenceEnvironment{{Environment: comid.Environment{Class: comid.NewClassBytes([]byte("platform-boot")).SetModel("boot")}, References: []manifest.Reference{{KeyType: "string", Key: "lead.firmware", Representation: "raw", Value: hex.EncodeToString([]byte("approved-platform-release-7"))}}}}, Variants: map[string]manifest.PlatformVariant{
		"single": {SKUs: []string{"blade-a"}, HardwareRevisions: []string{"rev2"}, Members: []manifest.ClassMember{first}},
		"dual":   {SKUs: []string{"blade-b"}, HardwareRevisions: []string{"rev2", "rev3"}, Members: []manifest.ClassMember{first, second}},
	}}
	sign := func(unsigned *corim.UnsignedCorim, issuer *demoKeyPair) ([]byte, error) {
		private, err := x509.MarshalECPrivateKey(issuer.Key)
		if err != nil {
			return nil, err
		}
		return compiler.SignDemoSnapshot(unsigned, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.DER}), issuer.Cert.Subject.CommonName)
	}
	unsigned, err := compiler.BuildPlatformClass(platform)
	if err != nil {
		return nil, err
	}
	platformBytes, err := sign(unsigned, platformSigner)
	if err != nil {
		return nil, err
	}
	unsigned, err = compiler.BuildComponentClass(component)
	if err != nil {
		return nil, err
	}
	componentBytes, err := sign(unsigned, componentSigner)
	if err != nil {
		return nil, err
	}
	result.Input = ClassProviderInput{Platform: platform, SignedPlatform: platformBytes, Components: map[string]ComponentClassSource{component.ID: {Manifest: component, SignedCoRIM: componentBytes}}, SignerScopes: map[string]string{"platform": fmt.Sprintf("%x", sha256.Sum256(platformSigner.DER)), component.ID: fmt.Sprintf("%x", sha256.Sum256(componentSigner.DER))}}
	leads := make([]*demoKeyPair, 2)
	claimsSets := make([]map[string][]byte, 2)
	for index, variantName := range []string{"single", "dual"} {
		lead, err := demoMakeCertificate(evidenceRoot.Cert, evidenceRoot.Key, false, fmt.Sprintf("Synthetic Server %d Lead", index), now)
		if err != nil {
			return nil, err
		}
		leads[index] = lead
		variant := platform.Variants[variantName]
		enrollment := manifest.InstanceEnrollment{ID: fmt.Sprintf("server-%d", index), Revision: "enrollment-1", Validity: validity, PlatformID: platform.ID, PlatformRevision: platform.Revision, Variant: variantName, SKU: variant.SKUs[0], HardwareRevision: "rev2", Lead: manifest.EnrolledIdentity{Class: platform.LeadClass, UEID: hex.EncodeToString(demoUEID(byte(0x10 + index*0x20))), PublicKeyPEM: demoPublicKeyPEM(&lead.Key.PublicKey)}, Members: map[string]manifest.EnrolledIdentity{}}
		claimsSets[index] = map[string][]byte{}
		for _, member := range variant.Members {
			device, err := demoMakeCertificate(evidenceRoot.Cert, evidenceRoot.Key, false, fmt.Sprintf("Synthetic Server %d %s", index, member.Label), now)
			if err != nil {
				return nil, err
			}
			enrollment.Members[member.Label] = manifest.EnrolledIdentity{Class: component.ComponentClass, PublicKeyPEM: demoPublicKeyPEM(&device.Key.PublicKey)}
			encoded, err := demoSPDMClaimsSet(evidenceRoot, device, result.Nonce, []byte("approved-controller-release-4"), false, spdmEvidenceMediaType)
			if err != nil {
				return nil, err
			}
			claimsSets[index][member.Label] = encoded
		}
		result.Input.Enrollments = append(result.Input.Enrollments, enrollment)
	}
	leadReferences, err := compiler.BuildReferenceValues(platform.LeadMeasurements)
	if err != nil {
		return nil, err
	}
	build := func(index int, sets map[string][]byte) ([]byte, error) {
		submods := map[string]any{}
		for label, value := range sets {
			digest := sha512.Sum384(value)
			submods[label] = []any{int64(sha384COSEAlgorithm), digest[:]}
		}
		ueid, err := hex.DecodeString(result.Input.Enrollments[index].Lead.UEID)
		if err != nil {
			return nil, err
		}
		return demoBundleFromClaimsSets(leads[index], evidenceRoot, ueid, result.Nonce, leadReferences, sets, submods)
	}
	for index := range leads {
		encoded, err := build(index, claimsSets[index])
		if err != nil {
			return nil, err
		}
		result.Bundles[fmt.Sprintf("server-%d-good", index)] = encoded
	}
	cross := map[string][]byte{first.Label: claimsSets[1][first.Label]}
	result.Bundles["server-0-cross-server"], err = build(0, cross)
	if err != nil {
		return nil, err
	}
	missing := map[string][]byte{first.Label: claimsSets[1][first.Label]}
	result.Bundles["server-1-missing-required"], err = build(1, missing)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func GenerateMixedDemoArtifacts(outputDirectory string) (*DemoManifest, error) {
	now := time.Now().UTC().Truncate(time.Second)
	endorsementRoot, err := demoMakeCertificate(nil, nil, true, "Mixed Demo Endorsement Root", now)
	if err != nil {
		return nil, err
	}
	endorser, err := demoMakeCertificate(endorsementRoot.Cert, endorsementRoot.Key, false, "Mixed Demo Snapshot Authority", now)
	if err != nil {
		return nil, err
	}
	sourceRoot, err := demoMakeCertificate(nil, nil, true, "Mixed Demo Source Root", now)
	if err != nil {
		return nil, err
	}
	sourceSigner, err := demoMakeCertificate(sourceRoot.Cert, sourceRoot.Key, false, "Mixed Demo Source Authority", now)
	if err != nil {
		return nil, err
	}
	leadRoot, err := demoMakeCertificate(nil, nil, true, "Mixed Demo Lead Root", now)
	if err != nil {
		return nil, err
	}
	lead, err := demoMakeCertificate(leadRoot.Cert, leadRoot.Key, false, "Mixed Demo Lead Attester", now)
	if err != nil {
		return nil, err
	}
	deviceLeaf, err := demoMakeCertificate(leadRoot.Cert, leadRoot.Key, false, "Mixed Strict Device EAT", now)
	if err != nil {
		return nil, err
	}
	deviceKey := deviceLeaf.Key
	spdmRoot, err := demoMakeCertificate(nil, nil, true, "Mixed Demo SPDM Root", now)
	if err != nil {
		return nil, err
	}
	spdmLeaf, err := demoMakeCertificate(spdmRoot.Cert, spdmRoot.Key, false, "Mixed Demo SPDM Device", now)
	if err != nil {
		return nil, err
	}

	leadUEID := demoUEID(0x10)
	deviceUEID := demoUEID(0x20)
	spdmUEID := demoUEID(0x30)
	deviceDigest := demoDigest("mixed-device-firmware-v1")
	spdmMeasurement := []byte("mixed-spdm-firmware-v1")
	validity := manifest.Validity{NotBefore: now.Add(-24 * time.Hour).Format(time.RFC3339), NotAfter: now.Add(365 * 24 * time.Hour).Format(time.RFC3339)}
	deviceVendor := manifest.VendorManifest{
		APIVersion: manifest.APIVersion, Kind: manifest.VendorKind,
		ID: "tag:example.com,2026:mixed-device", Validity: validity, Model: "device",
		EvidenceMediaType: eatContentType, IdentityPublicKeyPEM: demoPublicKeyPEM(&deviceKey.PublicKey),
		EvidencePolicy: manifest.EvidencePolicy{MediaType: eatContentType, DeviceMode: "strict"},
		ReferenceSetID: "device-fw-v1", References: []manifest.Reference{{
			KeyType: "string", Key: "device.firmware", Representation: "digest", Algorithm: "sha-384", Value: hex.EncodeToString(deviceDigest),
		}},
	}
	spdmVendor := manifest.VendorManifest{
		APIVersion: manifest.APIVersion, Kind: manifest.VendorKind,
		ID: "tag:example.com,2026:mixed-spdm", Validity: validity, Model: "spdm",
		EvidenceMediaType: spdmEvidenceMediaType, IdentityPublicKeyPEM: demoPublicKeyPEM(&spdmLeaf.Key.PublicKey),
		ReferenceSetID: "spdm-fw-v1", References: []manifest.Reference{{
			KeyType: "uint", Key: "1", Representation: "raw", Value: hex.EncodeToString(spdmMeasurement),
		}},
	}
	inventory := manifest.PlatformInventory{
		APIVersion: manifest.APIVersion, Kind: manifest.PlatformKind,
		ID: "tag:example.com,2026:mixed-platform", CompositeEATProfile: CompositeEATProfile,
		PlatformCoRIMProfile: PlatformCoRIMProfile, Validity: validity,
		Platform: manifest.Platform{
			Environment:      manifest.Environment{ClassID: "mixed-platform", Vendor: "Example", Model: "platform", Index: 0, UEID: hex.EncodeToString(leadUEID)},
			LeadPublicKeyPEM: demoPublicKeyPEM(&lead.Key.PublicKey),
			References:       []manifest.Reference{{KeyType: "string", Key: "lead.firmware", Representation: "digest", Algorithm: "sha-384", Value: hex.EncodeToString(demoDigest("mixed-lead-firmware-v1"))}},
		},
		Members: []manifest.Member{
			{Label: "env.device.0", Required: true, Environment: manifest.Environment{ClassID: "mixed-device", Vendor: "Example", Model: "device", Index: 0, UEID: hex.EncodeToString(deviceUEID)}, VendorManifest: "device-vendor.json", Collection: manifest.Collection{}},
			{Label: "env.spdm.0", Required: true, Environment: manifest.Environment{ClassID: "mixed-spdm", Vendor: "Example", Model: "spdm", Index: 0, UEID: hex.EncodeToString(spdmUEID)}, VendorManifest: "spdm-vendor.json", Collection: manifest.Collection{}},
		},
	}
	for index := range inventory.Members {
		endpoint := uint8(12 + index)
		inventory.Members[index].Collection.MCTPEID = &endpoint
	}
	registry := &manifest.ProfileRegistry{
		CompositeEAT:  manifest.ProfileEntry{ID: CompositeEATProfile, Status: "experimental", Version: "1.0.0"},
		PlatformCoRIM: manifest.ProfileEntry{ID: PlatformCoRIMProfile, Status: "experimental", Version: "0.5.0"},
	}
	sourceFiles := map[string]any{"source/platform.json": inventory, "source/device-vendor.json": deviceVendor, "source/spdm-vendor.json": spdmVendor}
	for name, value := range sourceFiles {
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := writeDemoFile(outputDirectory, name, append(encoded, '\n')); err != nil {
			return nil, err
		}
	}
	project, err := manifest.LoadProject(filepath.Join(outputDirectory, "source/platform.json"), registry)
	if err != nil {
		return nil, err
	}
	sourceKeyDER, err := x509.MarshalECPrivateKey(sourceSigner.Key)
	if err != nil {
		return nil, err
	}
	sourceKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sourceKeyDER})
	sourceCertificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sourceSigner.DER})
	platformSourceUnsigned, err := compiler.BuildPlatform(project, false)
	if err != nil {
		return nil, err
	}
	platformSource, err := compiler.SignDemoSnapshot(platformSourceUnsigned, sourceKeyPEM, sourceCertificatePEM, "Mixed Demo Source Authority")
	if err != nil {
		return nil, err
	}
	vendorSources := make(map[string][]byte, 2)
	for _, vendor := range []manifest.VendorManifest{deviceVendor, spdmVendor} {
		unsignedVendor, err := compiler.BuildVendor(vendor)
		if err != nil {
			return nil, err
		}
		vendorSources[vendor.ID], err = compiler.SignDemoSnapshot(unsignedVendor, sourceKeyPEM, sourceCertificatePEM, "Mixed Demo Source Authority")
		if err != nil {
			return nil, err
		}
	}
	snapshotKeyDER, err := x509.MarshalECPrivateKey(endorser.Key)
	if err != nil {
		return nil, err
	}
	sourceRoots := x509.NewCertPool()
	sourceRoots.AddCert(sourceRoot.Cert)
	sourceFingerprint := sha256.Sum256(sourceSigner.DER)
	signerScopes := map[string]string{"platform": hex.EncodeToString(sourceFingerprint[:]), deviceVendor.ID: hex.EncodeToString(sourceFingerprint[:]), spdmVendor.ID: hex.EncodeToString(sourceFingerprint[:])}
	platformCoRIM, authenticatedSourceDigests, err := compiler.CompileAuthenticatedDemoSnapshot(
		project, platformSource, vendorSources, sourceRoots, now,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: snapshotKeyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endorser.DER}),
		"Mixed Demo Snapshot Authority", signerScopes)
	if err != nil {
		return nil, err
	}
	endorsementRoots := x509.NewCertPool()
	endorsementRoots.AddCert(endorsementRoot.Cert)
	snapshot, err := LoadSnapshot(platformCoRIM, endorsementRoots, now)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	replayNonce := append([]byte(nil), nonce...)
	replayNonce[0] ^= 0xff
	deviceToken, err := demoStrictDeviceEAT(deviceLeaf, nonce, snapshot.Members["env.device.0"].ReferenceValues)
	if err != nil {
		return nil, err
	}
	deviceClaims, err := demoEncode(map[int64]any{cmwClaim: []any{eatContentType, deviceToken, uint64(4)}})
	if err != nil {
		return nil, err
	}
	goodSPDM, err := demoSPDMClaimsSet(spdmRoot, spdmLeaf, nonce, spdmMeasurement, false, spdmEvidenceMediaType)
	if err != nil {
		return nil, err
	}
	badSignature, err := demoSPDMClaimsSet(spdmRoot, spdmLeaf, nonce, spdmMeasurement, true, spdmEvidenceMediaType)
	if err != nil {
		return nil, err
	}
	replaySPDM, err := demoSPDMClaimsSet(spdmRoot, spdmLeaf, replayNonce, spdmMeasurement, false, spdmEvidenceMediaType)
	if err != nil {
		return nil, err
	}
	badMeasurement, err := demoSPDMClaimsSet(spdmRoot, spdmLeaf, nonce, []byte("unapproved-spdm-firmware"), false, spdmEvidenceMediaType)
	if err != nil {
		return nil, err
	}
	unsupported, err := demoSPDMClaimsSet(spdmRoot, spdmLeaf, nonce, spdmMeasurement, false, "application/example-unsupported")
	if err != nil {
		return nil, err
	}
	scenarios := map[string]map[string][]byte{
		"mixed-good.bundle.cbor":                 {"env.device.0": deviceClaims, "env.spdm.0": goodSPDM},
		"mixed-spdm-bad-signature.bundle.cbor":   {"env.device.0": deviceClaims, "env.spdm.0": badSignature},
		"mixed-spdm-replay.bundle.cbor":          {"env.device.0": deviceClaims, "env.spdm.0": replaySPDM},
		"mixed-spdm-bad-measurement.bundle.cbor": {"env.device.0": deviceClaims, "env.spdm.0": badMeasurement},
		"mixed-unsupported.bundle.cbor":          {"env.device.0": deviceClaims, "env.spdm.0": unsupported},
	}
	files := map[string][]byte{
		"platform.corim.cose":        platformCoRIM,
		"source-platform.corim.cose": platformSource,
		"source-device.corim.cose":   vendorSources[deviceVendor.ID],
		"source-spdm.corim.cose":     vendorSources[spdmVendor.ID],
		"source-roots.pem":           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sourceRoot.DER}),
		"endorsement-roots.pem":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endorsementRoot.DER}),
		"evidence-roots.pem":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leadRoot.DER}),
		"nonce.hex":                  []byte(hex.EncodeToString(nonce) + "\n"),
	}
	for name, claimsSets := range scenarios {
		submods := make(map[string]any, len(claimsSets))
		for label, claimsSet := range claimsSets {
			digest := sha512.Sum384(claimsSet)
			submods[label] = []any{int64(sha384COSEAlgorithm), digest[:]}
		}
		files[name], err = demoBundleFromClaimsSets(lead, leadRoot, leadUEID, nonce, snapshot.LeadReferenceValues, claimsSets, submods)
		if err != nil {
			return nil, err
		}
	}
	plan, err := compiler.MarshalCollectionPlan(project)
	if err != nil {
		return nil, err
	}
	files["composite.json"] = append(plan, '\n')
	files["source-authorizations.json"], err = demoJSON(signerScopes)
	if err != nil {
		return nil, err
	}
	sourceDigests := make(map[string]string, len(sourceFiles))
	for name := range sourceFiles {
		data, err := os.ReadFile(filepath.Join(outputDirectory, name))
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(data)
		sourceDigests[name] = hex.EncodeToString(digest[:])
	}
	artifactDigests := make(map[string]string, len(files))
	for name, data := range files {
		digest := sha256.Sum256(data)
		artifactDigests[name] = hex.EncodeToString(digest[:])
	}
	lock := manifest.ManifestLock{SchemaVersion: 1, ToolVersion: "platform-corim-v1alpha1", Sources: sourceDigests, Artifacts: artifactDigests}
	files["manifest.lock.json"], err = demoJSON(lock)
	if err != nil {
		return nil, err
	}
	provenanceDigests := make(map[string]string, len(sourceDigests)+len(authenticatedSourceDigests))
	for name, digest := range sourceDigests {
		provenanceDigests[name] = digest
	}
	for name, digest := range authenticatedSourceDigests {
		provenanceDigests["authenticated:"+name] = digest
	}
	provenance := manifest.SnapshotProvenance{
		Mode: "delegated-demo-snapshot", PlatformID: inventory.ID,
		Signer: "Mixed Demo Snapshot Authority", ValidUntil: validity.NotAfter,
		SourceDigests: provenanceDigests, SelectedReferenceSets: map[string]string{
			"env.device.0": deviceVendor.ReferenceSetID,
			"env.spdm.0":   spdmVendor.ReferenceSetID,
		},
	}
	files["snapshot-provenance.json"], err = demoJSON(provenance)
	if err != nil {
		return nil, err
	}
	report := manifest.ValidationReport{Valid: true, Profiles: *registry, Labels: compiler.Labels(project)}
	files["validation-report.json"], err = demoJSON(report)
	if err != nil {
		return nil, err
	}

	result := &DemoManifest{GeneratedAt: now.Format(time.RFC3339), Profile: PlatformCoRIMProfile, Nonce: hex.EncodeToString(nonce), Artifacts: map[string]string{}}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writeDemoFile(outputDirectory, name, files[name]); err != nil {
			return nil, err
		}
		digest := sha256.Sum256(files[name])
		result.Artifacts[name] = hex.EncodeToString(digest[:])
	}
	encodedManifest, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeDemoFile(outputDirectory, "manifest.json", append(encodedManifest, '\n')); err != nil {
		return nil, err
	}
	return result, nil
}

func demoJSON(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func demoSPDMClaimsSet(root, leaf *demoKeyPair, nonce, measurement []byte, corruptSignature bool, mediaType string) ([]byte, error) {
	vca := demoSPDMVCA()
	blockValue := append([]byte{0x81, byte(len(measurement)), 0}, measurement...)
	block := append([]byte{1, 1, byte(len(blockValue)), 0}, blockValue...)
	request := append([]byte{0x12, 0xe0, 1, 0xff}, nonce...)
	request = append(request, 0)
	response := make([]byte, 0, 8+len(block)+32+2)
	response = append(response, 0x12, 0x60, 0, 0, 1, byte(len(block)), 0, 0)
	response = append(response, block...)
	response = append(response, make([]byte, 32)...)
	response = append(response, 0, 0)
	transcript := append(append([]byte(nil), vca...), request...)
	transcript = append(transcript, response...)
	first := sha512.Sum384(transcript)
	context := make([]byte, 0, 148)
	for range 4 {
		context = append(context, "dmtf-spdm-v1.2.*"...)
	}
	context = append(context, 0)
	context = append(context, make([]byte, 100-len(context)-len("responder-measurements signing"))...)
	context = append(context, "responder-measurements signing"...)
	context = append(context, first[:]...)
	digest := sha512.Sum384(context)
	r, s, err := ecdsa.Sign(rand.Reader, leaf.Key, digest[:])
	if err != nil {
		return nil, err
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	if corruptSignature {
		signature[0] ^= 1
	}
	signedMeasurements := append([]byte(nil), transcript...)
	signedMeasurements = append(signedMeasurements, signature...)
	evidence, err := demoEncode([]any{signedMeasurements, append(append([]byte(nil), root.DER...), leaf.DER...)})
	if err != nil {
		return nil, err
	}
	return demoEncode(map[int64]any{cmwClaim: []any{mediaType, evidence, uint64(4)}})
}

func demoSPDMVCA() []byte {
	versionResponse := []byte{0x10, 0x04, 0, 0, 0, 1, 0, 0x12}
	getCapabilities := make([]byte, 20)
	copy(getCapabilities, []byte{0x12, 0xe1, 0, 0})
	capabilities := make([]byte, 20)
	copy(capabilities, []byte{0x12, 0x61, 0, 0})
	binary.LittleEndian.PutUint32(capabilities[8:12], 0x10)
	negotiate := make([]byte, 32)
	copy(negotiate, []byte{0x12, 0xe3, 0, 0})
	binary.LittleEndian.PutUint16(negotiate[4:6], uint16(len(negotiate)))
	negotiate[6] = 1
	binary.LittleEndian.PutUint32(negotiate[8:12], 1<<7)
	binary.LittleEndian.PutUint32(negotiate[12:16], 1<<1)
	algorithms := make([]byte, 36)
	copy(algorithms, []byte{0x12, 0x63, 0, 0})
	binary.LittleEndian.PutUint16(algorithms[4:6], uint16(len(algorithms)))
	algorithms[6] = 1
	binary.LittleEndian.PutUint32(algorithms[8:12], 1<<2)
	binary.LittleEndian.PutUint32(algorithms[12:16], 1<<7)
	binary.LittleEndian.PutUint32(algorithms[16:20], 1<<1)
	result := []byte{0x10, 0x84, 0, 0}
	result = append(result, versionResponse...)
	result = append(result, getCapabilities...)
	result = append(result, capabilities...)
	result = append(result, negotiate...)
	return append(result, algorithms...)
}

func writeDemoFile(root, name string, data []byte) error {
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
