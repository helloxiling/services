// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/veraison/corim/comid"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/compiler"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"
)

type ComponentClassSource struct {
	Manifest    manifest.ComponentReferenceManifest
	SignedCoRIM []byte
}

type ClassProviderInput struct {
	Platform       manifest.PlatformClassManifest
	SignedPlatform []byte
	Components     map[string]ComponentClassSource
	Enrollments    []manifest.InstanceEnrollment
	SignerScopes   map[string]string
	Compatibility  platformcorim.CompatibilityPolicy
}

type classSourceState struct {
	Digest    string
	NotBefore time.Time
	NotAfter  time.Time
}

type ClassProvider struct {
	input   ClassProviderInput
	sources map[string]classSourceState
	profile string
}

func NewClassProvider(input ClassProviderInput, roots *x509.CertPool, now time.Time) (*ClassProvider, error) {
	if now.IsZero() {
		now = time.Now()
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var ownedInput ClassProviderInput
	if err := json.Unmarshal(encoded, &ownedInput); err != nil {
		return nil, err
	}
	input = ownedInput
	unsigned, err := compiler.BuildPlatformClass(input.Platform)
	if err != nil {
		return nil, err
	}
	platform, err := compiler.AuthenticateClassSource(unsigned, input.SignedPlatform, roots, now, "platform", input.SignerScopes)
	if err != nil {
		return nil, fmt.Errorf("platform: %w", err)
	}
	provider := &ClassProvider{input: input, profile: input.Platform.CompositeEATProfile, sources: map[string]classSourceState{"platform": {Digest: platform.Digest, NotBefore: platform.NotBefore, NotAfter: platform.NotAfter}}}
	dependencies := map[string]bool{}
	for _, variant := range input.Platform.Variants {
		for _, member := range variant.Members {
			if member.ComponentID == "platform" {
				return nil, errors.New("component ID conflicts with platform scope")
			}
			dependencies[member.ComponentID] = true
			component, exists := input.Components[member.ComponentID]
			if !exists || component.Manifest.ID != member.ComponentID || component.Manifest.ComponentClass != member.ComponentClass || component.Manifest.ReferenceSetID != member.ReferenceSetID {
				return nil, fmt.Errorf("component dependency mismatch for %q", member.Label)
			}
		}
	}
	if len(input.Components) != len(dependencies) {
		return nil, errors.New("component sources do not match signed dependencies")
	}
	for id, component := range input.Components {
		unsigned, err := compiler.BuildComponentClass(component.Manifest)
		if err != nil {
			return nil, err
		}
		source, err := compiler.AuthenticateClassSource(unsigned, component.SignedCoRIM, roots, now, id, input.SignerScopes)
		if err != nil {
			return nil, fmt.Errorf("component %q: %w", id, err)
		}
		provider.sources[id] = classSourceState{Digest: source.Digest, NotBefore: source.NotBefore, NotAfter: source.NotAfter}
	}
	sourceDigests := make(map[string]string, len(provider.sources))
	for id, source := range provider.sources {
		sourceDigests[id] = source.Digest
	}
	if err := platformcorim.ValidateCompatibility(input.Compatibility, sourceDigests); err != nil {
		return nil, err
	}
	if len(input.Enrollments) == 0 {
		return nil, errors.New("trusted instance enrollment is required")
	}
	seenIDs, seenLeads, seenKeys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, enrollment := range input.Enrollments {
		decodedUEID, err := hex.DecodeString(enrollment.Lead.UEID)
		if err != nil {
			return nil, err
		}
		if seenIDs[enrollment.ID] || seenLeads[string(decodedUEID)] {
			return nil, errors.New("duplicate enrollment or Lead identity")
		}
		seenIDs[enrollment.ID], seenLeads[string(decodedUEID)] = true, true
		identities := []manifest.EnrolledIdentity{enrollment.Lead}
		for _, member := range enrollment.Members {
			identities = append(identities, member)
		}
		for _, identity := range identities {
			key, err := enrolledPublicKey(identity.PublicKeyPEM)
			if err != nil {
				return nil, err
			}
			der, err := x509.MarshalPKIXPublicKey(key)
			if err != nil {
				return nil, err
			}
			fingerprint := string(der)
			if seenKeys[fingerprint] {
				return nil, errors.New("attestation key assigned to multiple enrolled environments")
			}
			seenKeys[fingerprint] = true
		}
		if _, err := provider.resolveEnrollment(input, enrollment, now); err != nil {
			return nil, fmt.Errorf("enrollment %q: %w", enrollment.ID, err)
		}
	}
	return provider, nil
}

func enrolledPublicKey(value string) (crypto.PublicKey, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("enrollment requires exactly one public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if _, ok := key.(*ecdsa.PublicKey); !ok {
		return nil, errors.New("enrollment key algorithm is unsupported")
	}
	return key, nil
}

func (provider *ClassProvider) Resolve(ctx context.Context, request EndorsementRequest) (*EndorsementContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if provider == nil || provider.input.Platform.ID == "" {
		return nil, errors.New("class provider is not initialized")
	}
	input := provider.input
	if request.Profile != input.Platform.CompositeEATProfile {
		return nil, errors.New("evidence profile does not match platform class")
	}
	now := request.VerificationTime
	if now.IsZero() {
		now = time.Now()
	}
	for _, enrollment := range input.Enrollments {
		ueid, err := hex.DecodeString(enrollment.Lead.UEID)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(ueid, request.LeadUEID) {
			continue
		}
		key, err := enrolledPublicKey(enrollment.Lead.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		if !publicKeysEqual(key, request.LeadPublicKey) {
			return nil, errors.New("lead key does not match trusted enrollment")
		}
		return provider.resolveEnrollment(input, enrollment, now)
	}
	return nil, errors.New("lead identity has no trusted enrollment")
}

func (provider *ClassProvider) resolveEnrollment(input ClassProviderInput, enrollment manifest.InstanceEnrollment, now time.Time) (*Snapshot, error) {
	platform := input.Platform
	if enrollment.ID == "" || enrollment.Revision == "" || enrollment.PlatformID != platform.ID || enrollment.PlatformRevision != platform.Revision || enrollment.Lead.Class != platform.LeadClass {
		return nil, errors.New("enrollment does not match platform class/revision/Lead class")
	}
	variant, exists := platform.Variants[enrollment.Variant]
	if !exists || !slices.Contains(variant.SKUs, enrollment.SKU) || !slices.Contains(variant.HardwareRevisions, enrollment.HardwareRevision) {
		return nil, errors.New("enrollment SKU/hardware revision/variant is not endorsed")
	}
	notBefore, err := time.Parse(time.RFC3339, enrollment.Validity.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := time.Parse(time.RFC3339, enrollment.Validity.NotAfter)
	if err != nil {
		return nil, err
	}
	if !notAfter.After(notBefore) {
		return nil, errors.New("invalid enrollment validity")
	}
	sources := map[string]string{}
	include := func(id string) error {
		source, exists := provider.sources[id]
		if !exists {
			return errors.New("missing authenticated source")
		}
		if source.NotBefore.After(notBefore) {
			notBefore = source.NotBefore
		}
		if source.NotAfter.Before(notAfter) {
			notAfter = source.NotAfter
		}
		sources[id] = source.Digest
		return nil
	}
	if err := include("platform"); err != nil {
		return nil, err
	}
	leadUEID, err := hex.DecodeString(enrollment.Lead.UEID)
	if err != nil {
		return nil, err
	}
	instance, err := comid.NewUEIDInstance(leadUEID)
	if err != nil {
		return nil, err
	}
	leadKey, err := enrolledPublicKey(enrollment.Lead.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	if leadKey.(*ecdsa.PublicKey).Curve.Params().BitSize != 384 {
		return nil, errors.New("lead enrollment requires P-384")
	}
	environment := platform.Environment
	environment.Instance = instance
	leadReferences, err := compiler.BuildReferenceValues(platform.LeadMeasurements)
	if err != nil {
		return nil, err
	}
	result := &Snapshot{CoRIMID: platform.ID, Profile: manifest.ClassPlatformProfile, CompositeEATProfile: platform.CompositeEATProfile, Platform: environment, LeadKeys: []crypto.PublicKey{leadKey}, LeadReferenceValues: leadReferences, Members: map[string]MemberExpectation{}, SourceDigests: sources, EnrollmentID: enrollment.ID, EnrollmentRevision: enrollment.Revision, Variant: enrollment.Variant}
	known := map[string]bool{}
	for _, member := range variant.Members {
		known[member.Label] = true
		identity, present := enrollment.Members[member.Label]
		if !present {
			if member.Required {
				return nil, fmt.Errorf("required member %q is not enrolled", member.Label)
			}
			continue
		}
		if identity.Class != member.ComponentClass {
			return nil, errors.New("enrolled component class does not match role")
		}
		component := input.Components[member.ComponentID].Manifest
		if err := include(member.ComponentID); err != nil {
			return nil, err
		}
		key, err := enrolledPublicKey(identity.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		bits := key.(*ecdsa.PublicKey).Curve.Params().BitSize
		if component.Evidence.MediaType == spdmEvidenceMediaType {
			algorithm := fmt.Sprintf("ecdsa-p%d", bits)
			if !slices.Contains(component.Evidence.BaseAsym, algorithm) {
				return nil, errors.New("enrolled key not allowed by component Evidence policy")
			}
		} else if bits != 384 {
			return nil, errors.New("device EAT enrollment requires P-384")
		}
		var ueid []byte
		if identity.UEID != "" {
			ueid, err = hex.DecodeString(identity.UEID)
			if err != nil {
				return nil, err
			}
			if _, err = comid.NewUEIDInstance(ueid); err != nil {
				return nil, err
			}
		}
		references, err := compiler.BuildReferenceValues([]manifest.ReferenceEnvironment{{Environment: component.Environment, References: component.References}})
		if err != nil {
			return nil, err
		}
		carriage := platformcorim.CarriageCMW
		compatibility := false
		if authorization, ok := input.Compatibility.EvidenceCarriageBySource[member.ComponentID]; ok {
			carriage = authorization.Carriage
			compatibility = true
		}
		result.Members[member.Label] = MemberExpectation{Label: member.Label, Environment: component.Environment, Identity: ueid, IdentityKeys: []crypto.PublicKey{key}, ReferenceValues: references, Policy: manifest.MemberPolicy{Required: member.Required, ReferenceSet: member.ReferenceSetID, Evidence: component.Evidence}, SourceID: member.ComponentID, Carriage: carriage, Compatibility: compatibility}
	}
	for label := range enrollment.Members {
		if !known[label] {
			return nil, fmt.Errorf("enrollment contains unendorsed role %q", label)
		}
	}
	if now.Before(notBefore) || !now.Before(notAfter) {
		return nil, errors.New("class sources or enrollment are not currently valid")
	}
	result.ValidUntil = notAfter
	encoded, err := json.Marshal(struct {
		Sources    map[string]string
		Enrollment manifest.InstanceEnrollment
	}{sources, enrollment})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	result.Digest = hex.EncodeToString(digest[:])
	return result, nil
}

var _ EndorsementProvider = (*ClassProvider)(nil)

type EndorsementRequest struct {
	Profile          string
	LeadUEID         []byte
	LeadPublicKey    crypto.PublicKey
	ObservedLabels   []string
	VerificationTime time.Time
}

type EndorsementContext = Snapshot

type EndorsementProvider interface {
	Resolve(context.Context, EndorsementRequest) (*EndorsementContext, error)
}

type SnapshotProvider struct {
	Snapshot *Snapshot
}

func (p SnapshotProvider) Resolve(ctx context.Context, request EndorsementRequest) (*EndorsementContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.Snapshot == nil {
		return nil, errors.New("endorsement snapshot is not configured")
	}
	expectedProfile := p.Snapshot.CompositeEATProfile
	if expectedProfile == "" {
		expectedProfile = CompositeEATProfile
	}
	if request.Profile != expectedProfile {
		return nil, errors.New("authenticated profile is not supported by the snapshot provider")
	}
	if !request.VerificationTime.IsZero() && request.VerificationTime.After(p.Snapshot.ValidUntil) {
		return nil, errors.New("endorsement snapshot is expired")
	}
	if p.Snapshot.Platform.Instance == nil || !bytes.Equal(p.Snapshot.Platform.Instance.Bytes(), request.LeadUEID) {
		return nil, errors.New("lead Attester UEID is not authorized for the platform domain")
	}
	authorized := false
	for _, key := range p.Snapshot.LeadKeys {
		if publicKeysEqual(key, request.LeadPublicKey) {
			authorized = true
			break
		}
	}
	if !authorized {
		return nil, errors.New("lead Attester signing key is not authorized by the Platform CoRIM")
	}
	return p.Snapshot, nil
}

var _ EndorsementProvider = SnapshotProvider{}

type ClassSourceFiles = platformcorim.SourceFiles
type ClassPackage = platformcorim.ClassEndorsementPackage

func decodeClassJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing class package JSON")
	}
	return nil
}

func LoadClassProviderFile(path string, roots *x509.CertPool, now time.Time) (*ClassProvider, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	read := func(name string) ([]byte, error) {
		if name == "" || filepath.IsAbs(name) {
			return nil, errors.New("class package paths must be relative")
		}
		file, err := root.Open(name)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 16*1024*1024+1))
		if err != nil {
			return nil, err
		}
		if len(data) > 16*1024*1024 {
			return nil, errors.New("class package file exceeds size limit")
		}
		return data, nil
	}
	readPinned := func(name, digest string) ([]byte, error) {
		data, err := read(name)
		if err != nil {
			return nil, err
		}
		actual := fmt.Sprintf("%x", sha256.Sum256(data))
		if digest != actual {
			return nil, fmt.Errorf("class package hash mismatch for %q", name)
		}
		return data, nil
	}
	data, err := read(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	var config ClassPackage
	if err := decodeClassJSON(data, &config); err != nil {
		return nil, err
	}
	if config.APIVersion != manifest.APIVersion || config.Kind != "ClassEndorsementPackage" {
		return nil, errors.New("unsupported class package schema")
	}
	input := ClassProviderInput{Components: map[string]ComponentClassSource{}, SignerScopes: config.SignerScopes}
	if config.Compatibility != nil {
		input.Compatibility = *config.Compatibility
	}
	data, err = read(config.Platform.Manifest)
	if err != nil {
		return nil, err
	}
	if err := decodeClassJSON(data, &input.Platform); err != nil {
		return nil, err
	}
	input.SignedPlatform, err = readPinned(config.Platform.CoRIM, config.Platform.SHA256)
	if err != nil {
		return nil, err
	}
	for _, files := range config.Components {
		var component ComponentClassSource
		data, err = read(files.Manifest)
		if err != nil {
			return nil, err
		}
		if err := decodeClassJSON(data, &component.Manifest); err != nil {
			return nil, err
		}
		if _, exists := input.Components[component.Manifest.ID]; exists {
			return nil, errors.New("duplicate component source ID")
		}
		component.SignedCoRIM, err = readPinned(files.CoRIM, files.SHA256)
		if err != nil {
			return nil, err
		}
		input.Components[component.Manifest.ID] = component
	}
	data, err = readPinned(config.Enrollments, config.EnrollmentSHA256)
	if err != nil {
		return nil, err
	}
	if err := decodeClassJSON(data, &input.Enrollments); err != nil {
		return nil, err
	}
	return NewClassProvider(input, roots, now)
}

func LoadEndorsementProvider(snapshotPath, classPackagePath string, roots *x509.CertPool, profile string, now time.Time) (EndorsementProvider, error) {
	if (snapshotPath == "") == (classPackagePath == "") {
		return nil, errors.New("configure exactly one of platform-corim or class-package")
	}
	if err := manifest.ValidateProfileURI(profile); err != nil {
		return nil, err
	}
	if classPackagePath != "" {
		provider, err := LoadClassProviderFile(classPackagePath, roots, now)
		if err != nil {
			return nil, err
		}
		if provider.profile != profile {
			return nil, errors.New("configured Evidence profile does not match signed platform class")
		}
		return provider, nil
	}
	snapshot, err := LoadSnapshotFile(snapshotPath, roots, now)
	if err != nil {
		return nil, err
	}
	if snapshot.CompositeEATProfile != profile {
		return nil, errors.New("configured Composite EAT profile does not match signed snapshot")
	}
	return SnapshotProvider{Snapshot: snapshot}, nil
}
