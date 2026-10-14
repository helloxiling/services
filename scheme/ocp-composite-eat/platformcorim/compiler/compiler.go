// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package compiler

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

type CollectionPlan struct {
	Version                  int                `json:"-"`
	CompositeEATProfile      string             `json:"-"`
	PlatformID               string             `json:"-"`
	AllowUnknownEnvironments bool               `json:"allowUnknownEnvironments"`
	SkipDevices              []uint8            `json:"skipDevices"`
	Members                  []CollectionMember `json:"environments"`
}

type CollectionMember struct {
	Label             string              `json:"env"`
	Required          bool                `json:"-"`
	EvidenceMediaType string              `json:"-"`
	Collection        manifest.Collection `json:"match"`
}

func BuildPlatform(project *manifest.Project, includeVendorExpectations bool) (*corim.UnsignedCorim, error) {
	if project == nil {
		return nil, errors.New("project is nil")
	}
	notBefore, notAfter, err := parseValidity(project.Inventory.Validity)
	if err != nil {
		return nil, err
	}
	platformEnvironment, err := buildEnvironment(project.Inventory.Platform.Environment)
	if err != nil {
		return nil, err
	}
	leadKey, err := parsePublicKey(project.Inventory.Platform.LeadPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("lead public key: %w", err)
	}
	component := comid.NewComid().SetTagIdentity(project.Inventory.ID+":comid", 0)
	policy := &manifest.PolicyExtension{Binding: "demo-model-index-v1", Members: map[string]manifest.MemberPolicy{}}
	explicit := project.Inventory.PlatformCoRIMProfile == manifest.ExplicitPlatformProfile
	if explicit {
		policy.Binding = manifest.ExplicitBinding
		policy.CompositeEATProfile = project.Inventory.CompositeEATProfile
	}
	if err := manifest.RegisterPolicy(component, policy); err != nil {
		return nil, err
	}
	members := make([]comid.Environment, 0, len(project.Members))
	for _, resolved := range project.Members {
		memberPolicy := resolved.Vendor.Policy()
		memberPolicy.Required = resolved.Member.Required
		environment, err := buildEnvironment(resolved.Member.Environment)
		if err != nil {
			return nil, fmt.Errorf("member %q: %w", resolved.Member.Label, err)
		}
		if explicit {
			memberPolicy.Environment = &environment
		}
		policy.Members[resolved.Member.Label] = memberPolicy
		members = append(members, environment)
		if includeVendorExpectations {
			key, err := parsePublicKey(resolved.Vendor.IdentityPublicKeyPEM)
			if err != nil {
				return nil, fmt.Errorf("member %q identity key: %w", resolved.Member.Label, err)
			}
			component.AddAttestVerifKey(keyTriple(environment, key))
			for _, reference := range resolved.Vendor.References {
				triple, err := referenceTriple(environment, reference)
				if err != nil {
					return nil, fmt.Errorf("member %q: %w", resolved.Member.Label, err)
				}
				component.AddReferenceValue(triple)
			}
		}
	}
	component.Triples.AddDomainMembership(&comid.DomainMembershipTriple{DomainID: platformEnvironment, Members: members})
	component.AddAttestVerifKey(keyTriple(platformEnvironment, leadKey))
	groups := project.Inventory.Platform.MeasurementEnvironments
	if len(groups) == 0 {
		groups = []manifest.ReferenceEnvironment{{Environment: platformEnvironment, References: project.Inventory.Platform.References}}
	}
	for _, group := range groups {
		if explicit {
			policy.LeadEnvironments = append(policy.LeadEnvironments, group.Environment)
		}
		for _, reference := range group.References {
			triple, err := referenceTriple(group.Environment, reference)
			if err != nil {
				return nil, err
			}
			component.AddReferenceValue(triple)
		}
	}
	return corim.NewUnsignedCorim().
		SetID(project.Inventory.ID+":corim").
		SetProfile(project.Inventory.PlatformCoRIMProfile).
		SetRimValidity(notAfter, &notBefore).
		AddComid(component), nil
}

func BuildPlatformClass(source manifest.PlatformClassManifest) (*corim.UnsignedCorim, error) {
	if err := source.Validate(); err != nil {
		return nil, err
	}
	notBefore, notAfter, err := parseValidity(source.Validity)
	if err != nil {
		return nil, err
	}
	result := corim.NewUnsignedCorim().SetID(source.ID).SetProfile(manifest.ClassPlatformProfile).SetRimValidity(notAfter, &notBefore)
	variants := make([]string, 0, len(source.Variants))
	for name := range source.Variants {
		variants = append(variants, name)
	}
	sort.Strings(variants)
	for _, name := range variants {
		variant := source.Variants[name]
		component := comid.NewComid().SetTagIdentity(source.ID+":"+name, 0)
		policy := &manifest.PolicyExtension{Binding: "sku-group-v1", CompositeEATProfile: source.CompositeEATProfile, PlatformClass: &manifest.PlatformClassPolicy{ID: source.ID, Revision: source.Revision, LeadClass: source.LeadClass, Variant: name, Selection: variant}}
		if err := manifest.RegisterPolicy(component, policy); err != nil {
			return nil, err
		}
		members := make([]comid.Environment, 0, len(variant.Members))
		for index, member := range variant.Members {
			members = append(members, comid.Environment{Class: comid.NewClassBytes([]byte(member.ComponentClass)).SetIndex(uint64(index))})
		}
		component.Triples.AddDomainMembership(&comid.DomainMembershipTriple{DomainID: source.Environment, Members: members})
		for _, group := range source.LeadMeasurements {
			policy.LeadEnvironments = append(policy.LeadEnvironments, group.Environment)
			for _, reference := range group.References {
				triple, err := referenceTriple(group.Environment, reference)
				if err != nil {
					return nil, err
				}
				component.AddReferenceValue(triple)
			}
		}
		result.AddComid(component)
	}
	return result, nil
}

func BuildReferenceValues(groups []manifest.ReferenceEnvironment) ([]comid.ValueTriple, error) {
	var result []comid.ValueTriple
	for _, group := range groups {
		for _, reference := range group.References {
			triple, err := referenceTriple(group.Environment, reference)
			if err != nil {
				return nil, err
			}
			result = append(result, *triple)
		}
	}
	return result, nil
}

func ExportCocliInputs(unsigned *corim.UnsignedCorim) (map[string][]byte, error) {
	if unsigned == nil || len(unsigned.Tags) == 0 {
		return nil, errors.New("CoRIM with CoMID tags is required")
	}
	if _, err := unsigned.ToCBOR(); err != nil {
		return nil, err
	}
	envelope := *unsigned
	envelope.Tags = nil
	template, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{"corim-template.json": append(template, '\n')}
	for index, tag := range unsigned.Tags {
		if tag.Number != corim.ComidTag {
			return nil, errors.New("class export supports only CoMID tags")
		}
		files[fmt.Sprintf("comid-%03d.cbor", index)] = append([]byte(nil), tag.Content...)
	}
	return files, nil
}

func BuildComponentClass(source manifest.ComponentReferenceManifest) (*corim.UnsignedCorim, error) {
	if err := source.Validate(); err != nil {
		return nil, err
	}
	notBefore, notAfter, err := parseValidity(source.Validity)
	if err != nil {
		return nil, err
	}
	component := comid.NewComid().SetTagIdentity(source.ID+":comid", 0)
	policy := &manifest.PolicyExtension{Binding: "component-class-v1", ComponentClass: &manifest.ComponentClassPolicy{ID: source.ID, Class: source.ComponentClass, ReferenceSetID: source.ReferenceSetID, Evidence: source.Evidence}}
	if err := manifest.RegisterPolicy(component, policy); err != nil {
		return nil, err
	}
	for _, reference := range source.References {
		triple, err := referenceTriple(source.Environment, reference)
		if err != nil {
			return nil, err
		}
		component.AddReferenceValue(triple)
	}
	return corim.NewUnsignedCorim().SetID(source.ID).SetProfile(manifest.ClassComponentProfile).SetRimValidity(notAfter, &notBefore).AddComid(component), nil
}

func BuildVendor(vendor manifest.VendorManifest) (*corim.UnsignedCorim, error) {
	notBefore, notAfter, err := parseValidity(vendor.Validity)
	if err != nil {
		return nil, err
	}
	key, err := parsePublicKey(vendor.IdentityPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	environment := comid.Environment{Class: comid.NewClassBytes([]byte(vendor.ID)).SetModel(vendor.Model)}
	component := comid.NewComid().SetTagIdentity(vendor.ID+":comid", 0)
	policy := vendor.Policy()
	if err := manifest.RegisterPolicy(component, &manifest.PolicyExtension{Binding: "demo-model-index-v1", Vendor: &policy}); err != nil {
		return nil, err
	}
	component.AddAttestVerifKey(keyTriple(environment, key))
	for _, reference := range vendor.References {
		triple, err := referenceTriple(environment, reference)
		if err != nil {
			return nil, err
		}
		component.AddReferenceValue(triple)
	}
	return corim.NewUnsignedCorim().SetID(vendor.ID+":corim").SetRimValidity(notAfter, &notBefore).AddComid(component), nil
}

func BuildCollectionPlan(project *manifest.Project) CollectionPlan {
	plan := CollectionPlan{Version: 1, CompositeEATProfile: project.Inventory.CompositeEATProfile, PlatformID: project.Inventory.ID, SkipDevices: []uint8{}}
	for _, resolved := range project.Members {
		plan.Members = append(plan.Members, CollectionMember{
			Label: resolved.Member.Label, Required: resolved.Member.Required,
			EvidenceMediaType: resolved.Vendor.EvidenceMediaType, Collection: resolved.Member.Collection,
		})
	}
	return plan
}

func MarshalCollectionPlan(project *manifest.Project) ([]byte, error) {
	for _, member := range project.Members {
		locator := member.Member.Collection
		if locator.MCTPEID == nil && locator.PCIeBDF == "" && locator.I2CAddress == "" && locator.RedfishURI == "" {
			return nil, fmt.Errorf("collection locator missing for %q", member.Member.Label)
		}
	}
	return json.MarshalIndent(BuildCollectionPlan(project), "", "  ")
}

func SignDemoSnapshot(unsigned *corim.UnsignedCorim, privateKeyPEM, certificatePEM []byte, signerName string) ([]byte, error) {
	if unsigned == nil {
		return nil, errors.New("unsigned snapshot is nil")
	}
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		return nil, errors.New("signing certificate must be PEM encoded")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(&privateKey.PublicKey, certificate.PublicKey) {
		return nil, errors.New("signing key does not match certificate")
	}
	if unsigned.RimValidity == nil {
		return nil, errors.New("snapshot validity is required")
	}
	notBefore, notAfter := certificate.NotBefore, certificate.NotAfter
	if unsigned.RimValidity.NotBefore != nil && unsigned.RimValidity.NotBefore.After(notBefore) {
		notBefore = *unsigned.RimValidity.NotBefore
	}
	if unsigned.RimValidity.NotAfter.Before(notAfter) {
		notAfter = unsigned.RimValidity.NotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, errors.New("snapshot and signer validity do not overlap")
	}
	signer, err := cose.NewSigner(cose.AlgorithmES384, privateKey)
	if err != nil {
		return nil, err
	}
	signed := corim.NewSignedCorim()
	signed.UnsignedCorim = *unsigned
	signed.Meta = *corim.NewMeta().SetSigner(signerName, nil).SetValidity(notAfter, &notBefore)
	if err := signed.AddSigningCert(certificate.Raw); err != nil {
		return nil, err
	}
	return signed.Sign(signer)
}

func Labels(project *manifest.Project) []string {
	labels := make([]string, 0, len(project.Members))
	for _, member := range project.Members {
		labels = append(labels, member.Member.Label)
	}
	return labels
}

func buildEnvironment(source manifest.Environment) (comid.Environment, error) {
	ueid, err := hex.DecodeString(source.UEID)
	if err != nil {
		return comid.Environment{}, err
	}
	environment := comid.Environment{Class: comid.NewClassBytes([]byte(source.ClassID)).SetVendor(source.Vendor).SetModel(source.Model).SetIndex(source.Index)}
	if len(ueid) != 0 {
		environment.Instance, err = comid.NewUEIDInstance(ueid)
		if err != nil {
			return comid.Environment{}, err
		}
	}
	return environment, nil
}

func keyTriple(environment comid.Environment, key crypto.PublicKey) *comid.KeyTriple {
	encoded, _ := x509.MarshalPKIXPublicKey(key)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
	return &comid.KeyTriple{Environment: environment, VerifKeys: *comid.NewCryptoKeys().Add(comid.MustNewPKIXBase64Key(string(publicPEM)))}
}

func referenceTriple(environment comid.Environment, source manifest.Reference) (*comid.ValueTriple, error) {
	var key any = source.Key
	keyType := comid.StringType
	if source.KeyType == "uint" {
		parsed, err := strconv.ParseUint(source.Key, 10, 64)
		if err != nil {
			return nil, err
		}
		key, keyType = uint(parsed), comid.UintType
	}
	measurement, err := comid.NewMeasurement(key, keyType)
	if err != nil {
		return nil, err
	}
	value, err := hex.DecodeString(source.Value)
	if err != nil {
		return nil, err
	}
	measurement.Val.Flags, err = manifest.BuildFlags(source.Flags)
	if err != nil {
		return nil, err
	}
	if source.Representation == "raw" {
		measurement.SetRawValueBytes(value, nil)
	} else {
		algorithm := comid.Sha256
		switch source.Algorithm {
		case "sha-384":
			algorithm = comid.Sha384
		case "sha-512":
			algorithm = comid.Sha512
		}
		measurement.Val.Digests = &comid.Digests{*comid.NewDigestIntAlg(algorithm, value)}
	}
	return &comid.ValueTriple{Environment: environment, Measurements: *comid.NewMeasurements().Add(measurement)}, nil
}

func parsePublicKey(encoded string) (crypto.PublicKey, error) {
	if encoded == "" || containsPrivateKey(encoded) {
		return nil, errors.New("public key is missing or contains private material")
	}
	block, _ := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("key must be a PEM PUBLIC KEY")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func parsePrivateKey(encoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, errors.New("private key must be PEM encoded")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key must be ECDSA")
	}
	return key, nil
}

func containsPrivateKey(value string) bool {
	return len(value) > 0 && (contains(value, "PRIVATE KEY"))
}

func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

func parseValidity(validity manifest.Validity) (time.Time, time.Time, error) {
	notBefore, err := time.Parse(time.RFC3339, validity.NotBefore)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfter, err := time.Parse(time.RFC3339, validity.NotAfter)
	return notBefore, notAfter, err
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && string(leftDER) == string(rightDER)
}
