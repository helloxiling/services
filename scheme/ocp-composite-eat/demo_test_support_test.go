// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"

	"encoding/asn1"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/corim/coev"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

type DemoManifest struct {
	GeneratedAt string            `json:"generated-at"`
	Profile     string            `json:"platform-corim-profile"`
	Nonce       string            `json:"nonce"`
	Artifacts   map[string]string `json:"artifacts-sha256"`
}

type demoKeyPair struct {
	Key  *ecdsa.PrivateKey
	DER  []byte
	Cert *x509.Certificate
}

func GenerateDemoArtifacts(outputDirectory string) (*DemoManifest, error) {
	now := time.Now().UTC().Truncate(time.Second)
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return nil, err
	}

	endorsementRoot, err := demoMakeCertificate(nil, nil, true, "Demo Endorsement Root", now)
	if err != nil {
		return nil, err
	}
	endorser, err := demoMakeCertificate(endorsementRoot.Cert, endorsementRoot.Key, false, "Demo Platform Endorser", now)
	if err != nil {
		return nil, err
	}
	leadRoot, err := demoMakeCertificate(nil, nil, true, "Demo Lead Root", now)
	if err != nil {
		return nil, err
	}
	lead, err := demoMakeCertificate(leadRoot.Cert, leadRoot.Key, false, "Demo Lead Attester", now)
	if err != nil {
		return nil, err
	}
	devices := make([]*ecdsa.PrivateKey, 2)
	for index := range devices {
		devices[index], err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	leadUEID := demoUEID(0x10)
	platform := comid.Environment{
		Class:    comid.NewClassBytes([]byte("demo-platform")).SetModel("platform").SetIndex(0),
		Instance: comid.MustNewUEIDInstance(leadUEID),
	}
	members := make([]comid.Environment, len(devices))
	for index := range members {
		members[index] = comid.Environment{
			Class:    comid.NewClassBytes([]byte("demo-device")).SetModel("device").SetIndex(uint64(index)),
			Instance: comid.MustNewUEIDInstance(demoUEID(byte(0x20 + index*0x10))),
		}
	}

	component := comid.NewComid().SetTagIdentity("tag:example.com,2026:composite-eat-demo", 0)
	policy := &manifest.PolicyExtension{Binding: "demo-model-index-v1", Members: map[string]manifest.MemberPolicy{}}
	if err := manifest.RegisterPolicy(component, policy); err != nil {
		return nil, err
	}
	component.Triples.AddDomainMembership(&comid.DomainMembershipTriple{DomainID: platform, Members: members})
	component.AddAttestVerifKey(&comid.KeyTriple{
		Environment: platform,
		VerifKeys:   *comid.NewCryptoKeys().Add(comid.MustNewPKIXBase64Key(demoPublicKeyPEM(&lead.Key.PublicKey))),
	})
	component.AddReferenceValue(demoReferenceValue(platform, "lead.firmware", demoDigest("lead-firmware-v1")))
	for index, member := range members {
		policy.Members[fmt.Sprintf("env.device.%d", index)] = manifest.MemberPolicy{Required: true, ReferenceSet: "device-v1", Evidence: manifest.EvidencePolicy{MediaType: eatContentType, DeviceMode: "caliptra"}}
		component.AddAttestVerifKey(&comid.KeyTriple{
			Environment: member,
			VerifKeys:   *comid.NewCryptoKeys().Add(comid.MustNewPKIXBase64Key(demoPublicKeyPEM(&devices[index].PublicKey))),
		})
		component.AddReferenceValue(demoReferenceValue(member, "device.firmware", demoDigest(fmt.Sprintf("device-%d-firmware-v1", index))))
	}

	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)
	unsigned := corim.NewUnsignedCorim().
		SetID("tag:example.com,2026:composite-eat-demo-corim").
		SetProfile(PlatformCoRIMProfile).
		SetRimValidity(notAfter, &notBefore).
		AddComid(component)
	if unsigned == nil {
		return nil, fmt.Errorf("construct unsigned Platform CoRIM")
	}
	signer, err := cose.NewSigner(cose.AlgorithmES384, endorser.Key)
	if err != nil {
		return nil, err
	}
	signed := corim.NewSignedCorim()
	signed.UnsignedCorim = *unsigned
	signed.Meta = *corim.NewMeta().SetSigner("Composite EAT Demo Endorser", nil).SetValidity(notAfter, &notBefore)
	if err := signed.AddSigningCert(endorser.DER); err != nil {
		return nil, err
	}
	if err := signed.AddIntermediateCerts(endorsementRoot.DER); err != nil {
		return nil, err
	}
	platformCoRIM, err := signed.Sign(signer)
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
	oldNonce := append([]byte(nil), nonce...)
	oldNonce[0] ^= 0xff

	goodTokens := make(map[string][]byte, len(snapshot.Members))
	badFirmwareTokens := make(map[string][]byte, len(snapshot.Members))
	replayTokens := make(map[string][]byte, len(snapshot.Members))
	for index := range devices {
		label := fmt.Sprintf("env.device.%d", index)
		expectation := snapshot.Members[label]
		goodTokens[label], err = demoDeviceEAT(devices[index], nonce, expectation.ReferenceValues)
		if err != nil {
			return nil, err
		}
		badFirmwareTokens[label] = goodTokens[label]
		replayTokens[label] = goodTokens[label]
	}
	wrongReference := []comid.ValueTriple{*demoReferenceValue(members[1], "device.firmware", demoDigest("unapproved-firmware"))}
	badFirmwareTokens["env.device.1"], err = demoDeviceEAT(devices[1], nonce, wrongReference)
	if err != nil {
		return nil, err
	}
	replayTokens["env.device.1"], err = demoDeviceEAT(devices[1], oldNonce, snapshot.Members["env.device.1"].ReferenceValues)
	if err != nil {
		return nil, err
	}
	swappedTokens := map[string][]byte{
		"env.device.0": goodTokens["env.device.1"],
		"env.device.1": goodTokens["env.device.0"],
	}
	missingTokens := map[string][]byte{"env.device.0": goodTokens["env.device.0"]}

	files := map[string][]byte{
		"platform.corim.cose":   platformCoRIM,
		"endorsement-roots.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endorsementRoot.DER}),
		"evidence-roots.pem":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leadRoot.DER}),
		"nonce.hex":             []byte(hex.EncodeToString(nonce) + "\n"),
	}
	scenarios := map[string]map[string][]byte{
		"good.bundle.cbor":               goodTokens,
		"bad-firmware.bundle.cbor":       badFirmwareTokens,
		"replay.bundle.cbor":             replayTokens,
		"swapped-identities.bundle.cbor": swappedTokens,
		"missing-member.bundle.cbor":     missingTokens,
	}
	for name, tokens := range scenarios {
		files[name], err = demoBundle(lead, leadRoot, leadUEID, nonce, snapshot.LeadReferenceValues, tokens)
		if err != nil {
			return nil, fmt.Errorf("generate %s: %w", name, err)
		}
	}

	manifest := &DemoManifest{
		GeneratedAt: now.Format(time.RFC3339), Profile: PlatformCoRIMProfile,
		Nonce: hex.EncodeToString(nonce), Artifacts: make(map[string]string, len(files)),
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(outputDirectory, name)
		if err := os.WriteFile(path, files[name], 0o644); err != nil {
			return nil, err
		}
		digest := sha256.Sum256(files[name])
		manifest.Artifacts[name] = hex.EncodeToString(digest[:])
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(outputDirectory, "manifest.json"), append(manifestBytes, '\n'), 0o644); err != nil {
		return nil, err
	}
	return manifest, nil
}

func demoBundle(
	lead, leadRoot *demoKeyPair,
	leadUEID, nonce []byte,
	leadReferences []comid.ValueTriple,
	deviceTokens map[string][]byte,
) ([]byte, error) {
	claimsSets := make(map[string][]byte, len(deviceTokens))
	submods := make(map[string]any, len(deviceTokens))
	for label, token := range deviceTokens {
		claimsSet, err := demoEncode(map[int64]any{cmwClaim: []any{eatContentType, token, uint64(4)}})
		if err != nil {
			return nil, err
		}
		claimsSets[label] = claimsSet
		digest := sha512.Sum384(claimsSet)
		submods[label] = []any{int64(sha384COSEAlgorithm), digest[:]}
	}
	return demoBundleFromClaimsSets(lead, leadRoot, leadUEID, nonce, leadReferences, claimsSets, submods)
}

func demoBundleFromClaimsSets(
	lead, leadRoot *demoKeyPair,
	leadUEID, nonce []byte,
	leadReferences []comid.ValueTriple,
	claimsSets map[string][]byte,
	submods map[string]any,
) ([]byte, error) {

	concise := coev.NewConciseEvidence()
	triples := coev.NewEvTriples()
	for index := range leadReferences {
		triple := leadReferences[index]
		triples.AddEvidenceTriple(&triple)
	}
	if err := concise.AddTriples(triples); err != nil {
		return nil, err
	}
	leadEvidence, err := concise.ToCBOR()
	if err != nil {
		return nil, err
	}
	payload, err := demoEncode(map[int64]any{
		claimNonce: nonce, claimUEID: leadUEID,
		claimProfile:      CompositeEATProfile,
		claimSubmods:      submods,
		claimMeasurements: []any{[]any{uint64(conciseEvidenceFormat), leadEvidence}},
	})
	if err != nil {
		return nil, err
	}
	thumbprint := sha512.Sum384(lead.DER)
	protected, err := demoEncode(map[int64]any{
		headerAlgorithm: int64(es384COSEAlgorithm), headerContentType: eatContentType,
		headerX5Thumbprint: []any{int64(sha384COSEAlgorithm), thumbprint[:]},
	})
	if err != nil {
		return nil, err
	}
	signature, err := demoSign(protected, payload, lead.Key)
	if err != nil {
		return nil, err
	}
	mainToken, err := demoEncode(cbor.Tag{Number: cwtTag, Content: cbor.Tag{
		Number: coseSign1Tag, Content: []any{
			protected, map[int64]any{headerX5Chain: []any{lead.DER, leadRoot.DER}}, payload, signature,
		},
	}})
	if err != nil {
		return nil, err
	}
	return demoEncode(cbor.Tag{Number: detachedEATBundleTag, Content: []any{mainToken, claimsSets}})
}

func demoDeviceEAT(key *ecdsa.PrivateKey, nonce []byte, evidence []comid.ValueTriple) ([]byte, error) {
	concise := coev.NewConciseEvidence()
	triples := coev.NewEvTriples()
	for index := range evidence {
		triple := evidence[index]
		triples.AddEvidenceTriple(&triple)
	}
	if err := concise.AddTriples(triples); err != nil {
		return nil, err
	}
	tagged, err := coev.NewTaggedConciseEvidence(concise)
	if err != nil {
		return nil, err
	}
	encodedEvidence, err := tagged.ToCBOR()
	if err != nil {
		return nil, err
	}
	payload, err := demoEncode(map[int64]any{
		claimNonce: nonce, claimDebugStatus: uint64(1),
		claimProfile:      cbor.Tag{Number: oidTag, Content: []byte(deviceEATProfile)},
		claimMeasurements: []any{[]any{uint64(conciseEvidenceFormat), encodedEvidence}},
	})
	if err != nil {
		return nil, err
	}
	protected, err := demoEncode(map[int64]any{headerAlgorithm: int64(es384COSEAlgorithm)})
	if err != nil {
		return nil, err
	}
	signature, err := demoSign(protected, payload, key)
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	keyID := sha512.Sum384(publicDER)
	return demoEncode(cbor.Tag{Number: cborSelfDescribeTag, Content: cbor.Tag{
		Number: cwtTag, Content: cbor.Tag{Number: coseSign1Tag, Content: []any{
			protected, map[int64]any{headerKeyID: keyID[:]}, payload, signature,
		}},
	}})
}

func demoSign(protected, payload []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	sigStructure, err := demoEncode([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nil, err
	}
	digest := sha512.Sum384(sigStructure)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	return signature, nil
}

func demoReferenceValue(environment comid.Environment, key string, digest []byte) *comid.ValueTriple {
	return &comid.ValueTriple{
		Environment: environment,
		Measurements: *comid.NewMeasurements().Add(
			comid.MustNewMeasurement(key, comid.StringType).AddDigest(comid.Sha384, digest),
		),
	}
}

func demoDigest(value string) []byte {
	digest := sha512.Sum384([]byte(value))
	return digest[:]
}

func demoEncode(value any) ([]byte, error) {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(value)
}

func demoMakeCertificate(
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	isCA bool,
	commonName string,
	now time.Time,
) (*demoKeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, IsCA: isCA, BasicConstraintsValid: true,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		issuer = template
		issuerKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &demoKeyPair{Key: key, DER: der, Cert: cert}, nil
}

func demoPublicKeyPEM(key *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func demoUEID(start byte) []byte {
	value := make([]byte, 17)
	value[0] = 1
	for index := 1; index < len(value); index++ {
		value[index] = start + byte(index)
	}
	return value
}

func demoStrictDeviceEAT(leaf *demoKeyPair, nonce []byte, references []comid.ValueTriple) ([]byte, error) {
	legacy, err := demoDeviceEAT(leaf.Key, nonce, references)
	if err != nil {
		return nil, err
	}
	mode, err := strictDecMode(DefaultLimits())
	if err != nil {
		return nil, err
	}
	content, err := unwrapTags(legacy, mode, cborSelfDescribeTag, cwtTag, coseSign1Tag)
	if err != nil {
		return nil, err
	}
	var fields []cbor.RawMessage
	if err := mode.Unmarshal(content, &fields); err != nil {
		return nil, err
	}
	var payload []byte
	if err := mode.Unmarshal(fields[2], &payload); err != nil {
		return nil, err
	}
	var claims map[int64]any
	if err := mode.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	oid, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42623, 1, 3})
	if err != nil {
		return nil, err
	}
	claims[claimProfile] = oid[2:]
	payload, err = demoEncode(claims)
	if err != nil {
		return nil, err
	}
	protected, err := demoEncode(map[int64]any{headerAlgorithm: int64(-35), headerContentType: eatContentType})
	if err != nil {
		return nil, err
	}
	signature, err := demoSign(protected, payload, leaf.Key)
	if err != nil {
		return nil, err
	}
	return demoEncode(cbor.Tag{Number: cborSelfDescribeTag, Content: cbor.Tag{Number: cwtTag, Content: cbor.Tag{Number: coseSign1Tag, Content: []any{protected, map[int64]any{headerX5Chain: leaf.DER}, payload, signature}}}})
}
