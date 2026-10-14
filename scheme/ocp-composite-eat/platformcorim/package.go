// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platformcorim

import "fmt"

const (
	CarriageCMW       = "cmw-encoding"
	CarriageDirectMap = "direct-map"
)

type SourceFiles struct {
	Manifest string `json:"manifest"`
	CoRIM    string `json:"corim"`
	SHA256   string `json:"sha256"`
}

type CarriageAuthorization struct {
	SourceSHA256 string `json:"sourceSha256"`
	Carriage     string `json:"carriage"`
}

type CompatibilityPolicy struct {
	EvidenceCarriageBySource map[string]CarriageAuthorization `json:"evidenceCarriageBySource,omitempty"`
}

type ClassEndorsementPackage struct {
	APIVersion       string               `json:"apiVersion"`
	Kind             string               `json:"kind"`
	Platform         SourceFiles          `json:"platform"`
	Components       []SourceFiles        `json:"components"`
	Enrollments      string               `json:"enrollments"`
	EnrollmentSHA256 string               `json:"enrollmentSha256"`
	SignerScopes     map[string]string    `json:"signerScopes"`
	Compatibility    *CompatibilityPolicy `json:"compatibility,omitempty"`
}

func ValidateCompatibility(policy CompatibilityPolicy, sourceDigests map[string]string) error {
	for id, authorization := range policy.EvidenceCarriageBySource {
		digest, exists := sourceDigests[id]
		if !exists || id == "platform" {
			return fmt.Errorf("compatibility policy references unknown component source %q", id)
		}
		if authorization.Carriage != CarriageDirectMap {
			return fmt.Errorf("compatibility policy for %q uses unsupported carriage %q", id, authorization.Carriage)
		}
		if authorization.SourceSHA256 != digest {
			return fmt.Errorf("compatibility policy source digest mismatch for %q", id)
		}
	}
	return nil
}
