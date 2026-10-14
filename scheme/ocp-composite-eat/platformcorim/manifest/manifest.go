// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/extensions"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	APIVersion              = "composite-eat.ocp.org/v1alpha1"
	PlatformKind            = "PlatformInventory"
	VendorKind              = "DeviceReferenceValues"
	ExplicitPlatformProfile = "tag:example.com,2026:platform-composite-eat-explicit#0.5.0"
	ExplicitBinding         = "explicit-environment-v1"
	ClassPlatformProfile    = "tag:example.com,2026:platform-composite-eat-class#0.5.0"
	ClassComponentProfile   = "tag:example.com,2026:component-reference-class#0.5.0"
)

var labelPattern = regexp.MustCompile(`^env\.[a-z0-9]+\.[0-9]+$`)

var explicitLabelPattern = regexp.MustCompile(`^env\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)

type ProfileEntry struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

type ProfileRegistry struct {
	CompositeEAT          ProfileEntry  `json:"compositeEat"`
	PlatformCoRIM         ProfileEntry  `json:"platformCorim"`
	PlatformCoRIMExplicit *ProfileEntry `json:"platformCorimExplicit,omitempty"`
	PlatformClass         *ProfileEntry `json:"platformClass,omitempty"`
	ComponentClass        *ProfileEntry `json:"componentClass,omitempty"`
}

type Validity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

type Reference struct {
	KeyType        string          `json:"keyType"`
	Key            string          `json:"key"`
	Representation string          `json:"representation"`
	Algorithm      string          `json:"algorithm,omitempty"`
	Value          string          `json:"value"`
	Flags          map[string]bool `json:"flags,omitempty"`
}

type Environment struct {
	ClassID string `json:"classId"`
	Vendor  string `json:"vendor"`
	Model   string `json:"model"`
	Index   uint64 `json:"index"`
	UEID    string `json:"ueid"`
}

type Platform struct {
	Environment             Environment            `json:"environment"`
	LeadPublicKeyPEM        string                 `json:"leadPublicKeyPem"`
	References              []Reference            `json:"references"`
	MeasurementEnvironments []ReferenceEnvironment `json:"measurementEnvironments,omitempty"`
}

type ReferenceEnvironment struct {
	Environment comid.Environment `json:"environment"`
	References  []Reference       `json:"references"`
}

type ClassMember struct {
	Label          string `json:"label" cbor:"0,keyasint"`
	Required       bool   `json:"required" cbor:"1,keyasint"`
	ComponentID    string `json:"componentId" cbor:"2,keyasint"`
	ComponentClass string `json:"componentClass" cbor:"3,keyasint"`
	ReferenceSetID string `json:"referenceSetId" cbor:"4,keyasint"`
}

type PlatformVariant struct {
	SKUs              []string      `json:"skus" cbor:"0,keyasint"`
	HardwareRevisions []string      `json:"hardwareRevisions" cbor:"1,keyasint"`
	Members           []ClassMember `json:"members" cbor:"2,keyasint"`
}

type PlatformClassManifest struct {
	APIVersion          string                     `json:"apiVersion"`
	Kind                string                     `json:"kind"`
	ID                  string                     `json:"id"`
	Revision            string                     `json:"revision"`
	CompositeEATProfile string                     `json:"compositeEatProfile"`
	Validity            Validity                   `json:"validity"`
	Environment         comid.Environment          `json:"environment"`
	LeadClass           string                     `json:"leadClass"`
	LeadMeasurements    []ReferenceEnvironment     `json:"leadMeasurements"`
	Variants            map[string]PlatformVariant `json:"variants"`
}

type ComponentReferenceManifest struct {
	APIVersion     string            `json:"apiVersion"`
	Kind           string            `json:"kind"`
	ID             string            `json:"id"`
	ComponentClass string            `json:"componentClass"`
	Validity       Validity          `json:"validity"`
	ReferenceSetID string            `json:"referenceSetId"`
	Environment    comid.Environment `json:"environment"`
	Evidence       EvidencePolicy    `json:"evidence"`
	References     []Reference       `json:"references"`
}

type EnrolledIdentity struct {
	Class        string `json:"class"`
	UEID         string `json:"ueid,omitempty"`
	PublicKeyPEM string `json:"publicKeyPem"`
}

type InstanceEnrollment struct {
	ID               string                      `json:"id"`
	Revision         string                      `json:"revision"`
	Validity         Validity                    `json:"validity"`
	PlatformID       string                      `json:"platformId"`
	PlatformRevision string                      `json:"platformRevision"`
	Variant          string                      `json:"variant"`
	SKU              string                      `json:"sku"`
	HardwareRevision string                      `json:"hardwareRevision"`
	Lead             EnrolledIdentity            `json:"lead"`
	Members          map[string]EnrolledIdentity `json:"members"`
}

type PlatformClassPolicy struct {
	ID        string          `cbor:"0,keyasint"`
	Revision  string          `cbor:"1,keyasint"`
	LeadClass string          `cbor:"2,keyasint"`
	Variant   string          `cbor:"3,keyasint"`
	Selection PlatformVariant `cbor:"4,keyasint"`
}

type ComponentClassPolicy struct {
	ID             string         `cbor:"0,keyasint"`
	Class          string         `cbor:"1,keyasint"`
	ReferenceSetID string         `cbor:"2,keyasint"`
	Evidence       EvidencePolicy `cbor:"3,keyasint"`
}

func LoadPlatformClass(path string) (*PlatformClassManifest, error) {
	var result PlatformClassManifest
	if err := loadJSON(path, &result); err != nil {
		return nil, err
	}
	return &result, result.Validate()
}

func LoadComponentClass(path string) (*ComponentReferenceManifest, error) {
	var result ComponentReferenceManifest
	if err := loadJSON(path, &result); err != nil {
		return nil, err
	}
	return &result, result.Validate()
}

func ValidateClassEnvironment(environment comid.Environment) error {
	if environment.Class == nil || environment.Instance != nil || environment.Group != nil {
		return errors.New("class environment requires a class and forbids instance/group identity")
	}
	return environment.Valid()
}

func (value PlatformClassManifest) Validate() error {
	if value.APIVersion != APIVersion || value.Kind != "PlatformClassManifest" || value.ID == "" || value.Revision == "" || value.LeadClass == "" || len(value.Variants) == 0 || len(value.LeadMeasurements) == 0 {
		return errors.New("incomplete platform class manifest")
	}
	if err := ValidateProfileURI(value.CompositeEATProfile); err != nil {
		return err
	}
	if err := validateValidity(value.Validity); err != nil {
		return err
	}
	if err := ValidateClassEnvironment(value.Environment); err != nil {
		return err
	}
	for index, group := range value.LeadMeasurements {
		if err := ValidateClassEnvironment(group.Environment); err != nil {
			return err
		}
		if err := validateReferences(group.References); err != nil {
			return err
		}
		for _, previous := range value.LeadMeasurements[:index] {
			if reflect.DeepEqual(previous.Environment, group.Environment) {
				return errors.New("duplicate Lead measurement environment")
			}
		}
	}
	for name, variant := range value.Variants {
		if name == "" || len(variant.Members) == 0 || !uniqueNonempty(variant.SKUs) || !uniqueNonempty(variant.HardwareRevisions) {
			return errors.New("variant requires members, unique SKUs and hardware revisions")
		}
		labels := map[string]bool{}
		for _, member := range variant.Members {
			if !ValidExplicitLabel(member.Label) || labels[member.Label] || member.ComponentID == "" || member.ComponentClass == "" || member.ReferenceSetID == "" {
				return errors.New("invalid or duplicate class member")
			}
			labels[member.Label] = true
		}
	}
	return nil
}

func uniqueNonempty(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func (value ComponentReferenceManifest) Validate() error {
	if value.APIVersion != APIVersion || value.Kind != "ComponentReferenceManifest" || value.ID == "" || value.ComponentClass == "" || value.ReferenceSetID == "" {
		return errors.New("incomplete component class manifest")
	}
	if err := ValidateClassEnvironment(value.Environment); err != nil {
		return err
	}
	if err := validateValidity(value.Validity); err != nil {
		return err
	}
	if err := value.Evidence.Validate(); err != nil {
		return err
	}
	return validateReferences(value.References)
}

type Collection struct {
	MCTPEID    *uint8 `json:"mctpEid,omitempty"`
	PCIeBDF    string `json:"pcieBdf,omitempty"`
	I2CAddress string `json:"i2cAddr,omitempty"`
	RedfishURI string `json:"redfishUri,omitempty"`
}

type Member struct {
	Label          string      `json:"label"`
	Required       bool        `json:"required"`
	Environment    Environment `json:"environment"`
	VendorManifest string      `json:"vendorManifest"`
	Collection     Collection  `json:"collection"`
}

type PlatformInventory struct {
	APIVersion           string   `json:"apiVersion"`
	Kind                 string   `json:"kind"`
	ID                   string   `json:"id"`
	CompositeEATProfile  string   `json:"compositeEatProfile"`
	PlatformCoRIMProfile string   `json:"platformCorimProfile"`
	Validity             Validity `json:"validity"`
	Platform             Platform `json:"platform"`
	Members              []Member `json:"members"`
}

type VendorManifest struct {
	APIVersion           string         `json:"apiVersion"`
	Kind                 string         `json:"kind"`
	ID                   string         `json:"id"`
	Validity             Validity       `json:"validity"`
	Model                string         `json:"model"`
	EvidenceMediaType    string         `json:"evidenceMediaType"`
	IdentityPublicKeyPEM string         `json:"identityPublicKeyPem"`
	ReferenceSetID       string         `json:"referenceSetId"`
	References           []Reference    `json:"references"`
	EvidencePolicy       EvidencePolicy `json:"evidencePolicy,omitempty"`
}

type ResolvedMember struct {
	Member Member
	Vendor VendorManifest
}

type Project struct {
	SourcePath string
	Inventory  PlatformInventory
	Members    []ResolvedMember
}

type ManifestLock struct {
	SchemaVersion int               `json:"schemaVersion"`
	ToolVersion   string            `json:"toolVersion"`
	Sources       map[string]string `json:"sourcesSha256"`
	Artifacts     map[string]string `json:"artifactsSha256"`
}

type SnapshotProvenance struct {
	Mode                  string            `json:"mode"`
	PlatformID            string            `json:"platformId"`
	Signer                string            `json:"signer"`
	ValidUntil            string            `json:"validUntil"`
	SourceDigests         map[string]string `json:"sourceDigests"`
	SelectedReferenceSets map[string]string `json:"selectedReferenceSets"`
}

type ValidationReport struct {
	Valid    bool            `json:"valid"`
	Profiles ProfileRegistry `json:"profiles"`
	Labels   []string        `json:"labels"`
}

func LoadRegistry(path string) (*ProfileRegistry, error) {
	var registry ProfileRegistry
	if err := loadJSON(path, &registry); err != nil {
		return nil, err
	}
	if registry.CompositeEAT.Status != "experimental" || registry.PlatformCoRIM.Status != "experimental" ||
		registry.CompositeEAT.ID == "" || registry.PlatformCoRIM.ID == "" {
		return nil, errors.New("profile registry must contain experimental Composite EAT and Platform CoRIM entries")
	}
	return &registry, nil
}

func LoadProject(path string, registry *ProfileRegistry) (*Project, error) {
	return LoadProjectAtRoot(path, registry, filepath.Dir(path))
}

func LoadProjectAtRoot(path string, registry *ProfileRegistry, packageRoot string) (*Project, error) {
	var inventory PlatformInventory
	if err := loadJSON(path, &inventory); err != nil {
		return nil, err
	}
	if err := inventory.Validate(registry); err != nil {
		return nil, err
	}
	project := &Project{SourcePath: path, Inventory: inventory}
	base := filepath.Dir(path)
	root, err := filepath.Abs(packageRoot)
	if err != nil {
		return nil, err
	}
	confined, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer confined.Close()
	for _, member := range inventory.Members {
		vendorPath := member.VendorManifest
		if filepath.IsAbs(vendorPath) {
			return nil, fmt.Errorf("member %q vendor manifest must be relative to the package root", member.Label)
		}
		vendorPath, err = filepath.Abs(filepath.Join(base, vendorPath))
		if err != nil {
			return nil, err
		}
		relative, err := filepath.Rel(root, vendorPath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("member %q vendor manifest escapes package root", member.Label)
		}
		var vendor VendorManifest
		data, readErr := confined.ReadFile(relative)
		if readErr != nil {
			return nil, fmt.Errorf("vendor manifest escapes package root or cannot be read: %w", readErr)
		}
		if err := decodeJSON(data, &vendor); err != nil {
			return nil, fmt.Errorf("member %q vendor manifest: %w", member.Label, err)
		}
		if err := vendor.Validate(); err != nil {
			return nil, fmt.Errorf("member %q vendor manifest: %w", member.Label, err)
		}
		if vendor.Model != member.Environment.Model {
			return nil, fmt.Errorf("member %q model %q does not match vendor model %q", member.Label, member.Environment.Model, vendor.Model)
		}
		project.Members = append(project.Members, ResolvedMember{Member: member, Vendor: vendor})
	}
	return project, nil
}

func LoadVendor(path string) (*VendorManifest, error) {
	var vendor VendorManifest
	if err := loadJSON(path, &vendor); err != nil {
		return nil, err
	}
	if err := vendor.Validate(); err != nil {
		return nil, err
	}
	return &vendor, nil
}

func (p PlatformInventory) Validate(registry *ProfileRegistry) error {
	if p.APIVersion != APIVersion || p.Kind != PlatformKind {
		return errors.New("unsupported platform manifest schema")
	}
	explicit := p.PlatformCoRIMProfile == ExplicitPlatformProfile
	profileAllowed := registry != nil && p.PlatformCoRIMProfile == registry.PlatformCoRIM.ID
	if registry != nil && explicit && registry.PlatformCoRIMExplicit != nil {
		profileAllowed = registry.PlatformCoRIMExplicit.ID == ExplicitPlatformProfile && registry.PlatformCoRIMExplicit.Status == "experimental"
	}
	if !profileAllowed || registry == nil || p.CompositeEATProfile != registry.CompositeEAT.ID {
		return errors.New("platform profiles do not match the checked registry")
	}
	if explicit {
		if err := ValidateProfileURI(p.CompositeEATProfile); err != nil {
			return err
		}
	}
	if p.ID == "" || len(p.Members) == 0 {
		return errors.New("platform ID and members are required")
	}
	if strings.Contains(p.Platform.LeadPublicKeyPEM, "PRIVATE KEY") {
		return errors.New("private keys are forbidden in platform manifests")
	}
	if err := validateValidity(p.Validity); err != nil {
		return err
	}
	if err := validateEnvironment(p.Platform.Environment, true); err != nil {
		return fmt.Errorf("platform environment: %w", err)
	}
	labels := make(map[string]struct{}, len(p.Members))
	for _, member := range p.Members {
		if (explicit && !ValidExplicitLabel(member.Label)) || (!explicit && !labelPattern.MatchString(member.Label)) {
			return fmt.Errorf("invalid member label %q", member.Label)
		}
		expected := fmt.Sprintf("env.%s.%d", member.Environment.Model, member.Environment.Index)
		if !explicit && member.Label != expected {
			return fmt.Errorf("member label %q does not match model/index %q", member.Label, expected)
		}
		if _, exists := labels[member.Label]; exists {
			return fmt.Errorf("duplicate member label %q", member.Label)
		}
		labels[member.Label] = struct{}{}
		if err := validateEnvironment(member.Environment, !explicit || member.Environment.UEID != ""); err != nil {
			return fmt.Errorf("member %q environment: %w", member.Label, err)
		}
		if member.VendorManifest == "" {
			return fmt.Errorf("member %q vendor manifest is required", member.Label)
		}
	}
	if len(p.Platform.MeasurementEnvironments) != 0 {
		if !explicit || len(p.Platform.References) != 0 {
			return errors.New("separate measurement environments require the explicit profile and no legacy references")
		}
		for _, group := range p.Platform.MeasurementEnvironments {
			if err := group.Environment.Valid(); err != nil {
				return fmt.Errorf("measurement environment: %w", err)
			}
			if err := validateReferences(group.References); err != nil {
				return err
			}
		}
		return nil
	}
	return validateReferences(p.Platform.References)
}

func ValidExplicitLabel(label string) bool {
	return len(label) <= 64 && explicitLabelPattern.MatchString(label)
}

func ValidateProfileURI(profile string) error {
	parsed, err := url.Parse(profile)
	if err != nil || parsed.Scheme == "" || strings.TrimSpace(profile) != profile {
		return errors.New("composite EAT profile must be an absolute URI")
	}
	return nil
}

func (v VendorManifest) Validate() error {
	if v.APIVersion != APIVersion || v.Kind != VendorKind {
		return errors.New("unsupported vendor manifest schema")
	}
	if v.ID == "" || v.Model == "" || v.EvidenceMediaType == "" || v.ReferenceSetID == "" {
		return errors.New("vendor ID, model, Evidence media type, and reference set are required")
	}
	if strings.Contains(v.ID, "env.") {
		return errors.New("vendor manifests must not contain platform labels")
	}
	if strings.Contains(v.IdentityPublicKeyPEM, "PRIVATE KEY") {
		return errors.New("private keys are forbidden in vendor manifests")
	}
	if err := validateValidity(v.Validity); err != nil {
		return err
	}
	if v.EvidencePolicy.MediaType != "" && v.EvidencePolicy.MediaType != v.EvidenceMediaType {
		return errors.New("conflicting Evidence media types")
	}
	if err := v.Policy().Evidence.Validate(); err != nil {
		return err
	}
	return validateReferences(v.References)
}

func validateValidity(validity Validity) error {
	notBefore, beforeErr := time.Parse(time.RFC3339, validity.NotBefore)
	notAfter, afterErr := time.Parse(time.RFC3339, validity.NotAfter)
	if beforeErr != nil || afterErr != nil || !notAfter.After(notBefore) {
		return errors.New("validity must contain ordered RFC3339 times")
	}
	return nil
}

func validateEnvironment(environment Environment, requireUEID bool) error {
	if environment.ClassID == "" || environment.Vendor == "" || environment.Model == "" {
		return errors.New("class ID, vendor, and model are required")
	}
	if requireUEID {
		decoded, err := hex.DecodeString(environment.UEID)
		if err != nil || len(decoded) < 7 || len(decoded) > 33 {
			return errors.New("UEID must be 7-to-33 bytes of hexadecimal")
		}
	}
	return nil
}

func validateReferences(references []Reference) error {
	if len(references) == 0 {
		return errors.New("at least one reference value is required")
	}
	for _, reference := range references {
		if reference.KeyType != "string" && reference.KeyType != "uint" {
			return fmt.Errorf("unsupported reference key type %q", reference.KeyType)
		}
		if reference.Key == "" || (reference.Representation != "raw" && reference.Representation != "digest") {
			return errors.New("reference key and representation are required")
		}
		value, err := hex.DecodeString(reference.Value)
		if err != nil || len(value) == 0 {
			return errors.New("reference value must be non-empty hexadecimal")
		}
		if reference.Representation == "digest" && reference.Algorithm != "sha-384" && reference.Algorithm != "sha-256" && reference.Algorithm != "sha-512" {
			return fmt.Errorf("unsupported digest algorithm %q", reference.Algorithm)
		}
		if _, err := BuildFlags(reference.Flags); err != nil {
			return err
		}
	}
	return nil
}

func BuildFlags(values map[string]bool) (*comid.FlagsMap, error) {
	if len(values) == 0 {
		return nil, nil
	}
	known := map[string]comid.Flag{
		"is-configured": comid.FlagIsConfigured, "is-secure": comid.FlagIsSecure,
		"is-recovery": comid.FlagIsRecovery, "is-debug": comid.FlagIsDebug,
		"is-replay-protected":    comid.FlagIsReplayProtected,
		"is-integrity-protected": comid.FlagIsIntegrityProtected,
		"is-runtime-meas":        comid.FlagIsRuntimeMeasured, "is-immutable": comid.FlagIsImmutable,
		"is-tcb": comid.FlagIsTcb, "is-confidentiality-protected": comid.FlagIsConfidentialityProtected,
	}
	flags := comid.NewFlagsMap()
	for name, value := range values {
		flag, exists := known[name]
		if !exists {
			return nil, fmt.Errorf("unsupported measurement flag %q", name)
		}
		if value {
			flags.SetTrue(flag)
		} else {
			flags.SetFalse(flag)
		}
	}
	return flags, nil
}

func loadJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return decodeJSON(data, target)
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

const (
	SPDMMeasurementTypePolicyVersionStrict = "version-strict"
	SPDMMeasurementTypePolicyKnownTypes    = "known-types"
)

type EvidencePolicy struct {
	MediaType                 string   `json:"mediaType" cbor:"0,keyasint"`
	DeviceMode                string   `json:"deviceMode,omitempty" cbor:"1,keyasint,omitempty"`
	SPDMVersions              []uint16 `json:"spdmVersions,omitempty" cbor:"2,keyasint,omitempty"`
	BaseHashes                []string `json:"baseHashes,omitempty" cbor:"3,keyasint,omitempty"`
	BaseAsym                  []string `json:"baseAsym,omitempty" cbor:"4,keyasint,omitempty"`
	SPDMMeasurementTypePolicy string   `json:"spdmMeasurementTypePolicy,omitempty" cbor:"5,keyasint,omitempty"`
}

type MemberPolicy struct {
	Required     bool               `json:"required" cbor:"0,keyasint"`
	ReferenceSet string             `json:"referenceSet" cbor:"1,keyasint"`
	Evidence     EvidencePolicy     `json:"evidence" cbor:"2,keyasint"`
	Environment  *comid.Environment `json:"environment,omitempty" cbor:"3,keyasint,omitempty"`
}

type PolicyExtension struct {
	Binding             string                  `json:"demo-binding" cbor:"-1,keyasint"`
	Members             map[string]MemberPolicy `json:"demo-members,omitempty" cbor:"-2,keyasint,omitempty"`
	Vendor              *MemberPolicy           `json:"demo-vendor,omitempty" cbor:"-3,keyasint,omitempty"`
	CompositeEATProfile string                  `json:"composite-eat-profile,omitempty" cbor:"-4,keyasint,omitempty"`
	LeadEnvironments    []comid.Environment     `json:"lead-environments,omitempty" cbor:"-5,keyasint,omitempty"`
	PlatformClass       *PlatformClassPolicy    `json:"platform-class,omitempty" cbor:"-6,keyasint,omitempty"`
	ComponentClass      *ComponentClassPolicy   `json:"component-class,omitempty" cbor:"-7,keyasint,omitempty"`
}

func RegisterPolicy(component *comid.Comid, policy *PolicyExtension) error {
	return component.RegisterExtensions(extensions.NewMap().Add(comid.ExtComid, policy))
}

func (v VendorManifest) Policy() MemberPolicy {
	policy := v.EvidencePolicy
	if policy.MediaType == "" {
		policy.MediaType = v.EvidenceMediaType
	}
	if policy.MediaType == "application/spdm-evidence+cbor" && len(policy.SPDMVersions) == 0 {
		policy.SPDMVersions = []uint16{0x12}
		policy.BaseHashes = []string{"sha-384"}
		policy.BaseAsym = []string{"ecdsa-p384"}
	}
	if policy.MediaType == "application/eat+cwt" && policy.DeviceMode == "" {
		policy.DeviceMode = "strict"
	}
	return MemberPolicy{Required: true, ReferenceSet: v.ReferenceSetID, Evidence: policy}
}

func (p EvidencePolicy) Validate() error {
	switch p.MediaType {
	case "application/eat+cwt":
		if p.DeviceMode != "strict" && p.DeviceMode != "caliptra" {
			return errors.New("unsupported Device EAT mode")
		}
		if p.SPDMMeasurementTypePolicy != "" {
			return errors.New("SPDM measurement-type policy requires SPDM Evidence")
		}
	case "application/spdm-evidence+cbor":
		if len(p.SPDMVersions) == 0 || len(p.BaseHashes) == 0 || len(p.BaseAsym) == 0 {
			return errors.New("SPDM policy must explicitly bound versions and algorithms")
		}
		if p.SPDMMeasurementTypePolicy != "" &&
			p.SPDMMeasurementTypePolicy != SPDMMeasurementTypePolicyVersionStrict &&
			p.SPDMMeasurementTypePolicy != SPDMMeasurementTypePolicyKnownTypes {
			return errors.New("unsupported SPDM measurement-type policy")
		}
		for _, version := range p.SPDMVersions {
			if version != 0x10 && version != 0x12 {
				return errors.New("unsupported SPDM policy version")
			}
		}
		for _, hash := range p.BaseHashes {
			if hash != "sha-256" && hash != "sha-384" {
				return errors.New("unsupported SPDM policy hash")
			}
		}
		for _, asym := range p.BaseAsym {
			if asym != "ecdsa-p256" && asym != "ecdsa-p384" {
				return errors.New("unsupported SPDM policy asymmetric algorithm")
			}
		}
	default:
		return errors.New("unsupported Evidence media type")
	}
	return nil
}
