// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package compiler

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/veraison/corim/corim"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

type AuthenticatedSource struct {
	Unsigned           *corim.UnsignedCorim
	Digest             string
	SigningCertificate *x509.Certificate
	NotBefore          time.Time
	NotAfter           time.Time
}

func AuthenticateClassSource(expected *corim.UnsignedCorim, data []byte, roots *x509.CertPool, currentTime time.Time, scope string, scopes map[string]string) (*AuthenticatedSource, error) {
	source, err := AuthenticateSource(data, roots, currentTime)
	if err != nil {
		return nil, err
	}
	if err := authorizeSource(source, scope, scopes); err != nil {
		return nil, err
	}
	if err := sameUnsignedCoRIM(expected, source.Unsigned); err != nil {
		return nil, fmt.Errorf("class source drift: %w", err)
	}
	return source, nil
}

func AuthenticateSource(data []byte, roots *x509.CertPool, currentTime time.Time) (*AuthenticatedSource, error) {
	if roots == nil || len(data) == 0 {
		return nil, errors.New("source CoRIM and independently configured roots are required")
	}
	signed, err := corim.UnmarshalAndValidateSignedCorimFromCBOR(data)
	if err != nil {
		return nil, fmt.Errorf("decode signed source CoRIM: %w", err)
	}
	if signed.SigningCert == nil {
		return nil, errors.New("source CoRIM has no signing certificate")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range signed.IntermediateCerts {
		intermediates.AddCert(certificate)
	}
	chains, err := signed.SigningCert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: currentTime,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("validate source CoRIM signer: %w", err)
	}
	if err := signed.Verify(signed.SigningCert.PublicKey); err != nil {
		return nil, fmt.Errorf("verify source CoRIM signature: %w", err)
	}
	if err := sourceValidity("source CoRIM signer metadata", signed.Meta.Validity, currentTime); err != nil {
		return nil, err
	}
	if err := sourceValidity("source CoRIM", signed.UnsignedCorim.RimValidity, currentTime); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	unsigned := signed.UnsignedCorim
	notBefore, notAfter := signed.SigningCert.NotBefore, signed.SigningCert.NotAfter
	for _, certificate := range chains[0] {
		if certificate.NotBefore.After(notBefore) {
			notBefore = certificate.NotBefore
		}
		if certificate.NotAfter.Before(notAfter) {
			notAfter = certificate.NotAfter
		}
	}
	for _, validity := range []*corim.Validity{signed.Meta.Validity, unsigned.RimValidity} {
		if validity.NotBefore != nil && validity.NotBefore.After(notBefore) {
			notBefore = *validity.NotBefore
		}
		if validity.NotAfter.Before(notAfter) {
			notAfter = validity.NotAfter
		}
	}
	return &AuthenticatedSource{Unsigned: &unsigned, Digest: hex.EncodeToString(digest[:]), SigningCertificate: signed.SigningCert, NotBefore: notBefore, NotAfter: notAfter}, nil
}

func CompileAuthenticatedDemoSnapshot(
	project *manifest.Project,
	platformSource []byte,
	vendorSources map[string][]byte,
	sourceRoots *x509.CertPool,
	currentTime time.Time,
	snapshotPrivateKeyPEM, snapshotCertificatePEM []byte,
	snapshotSigner string,
	signerScopes map[string]string,
) ([]byte, map[string]string, error) {
	expectedPlatform, err := BuildPlatform(project, false)
	if err != nil {
		return nil, nil, err
	}
	authenticatedPlatform, err := AuthenticateSource(platformSource, sourceRoots, currentTime)
	if err != nil {
		return nil, nil, fmt.Errorf("platform source: %w", err)
	}
	if err := authorizeSource(authenticatedPlatform, "platform", signerScopes); err != nil {
		return nil, nil, err
	}
	notBefore, notAfter := authenticatedPlatform.NotBefore, authenticatedPlatform.NotAfter
	if err := sameUnsignedCoRIM(expectedPlatform, authenticatedPlatform.Unsigned); err != nil {
		return nil, nil, fmt.Errorf("platform source drift: %w", err)
	}
	provenance := map[string]string{"platform": authenticatedPlatform.Digest}
	expectedVendorIDs := make(map[string]struct{}, len(project.Members))
	for _, resolved := range project.Members {
		expectedVendorIDs[resolved.Vendor.ID] = struct{}{}
	}
	if len(vendorSources) != len(expectedVendorIDs) {
		return nil, nil, errors.New("vendor source count does not match platform members")
	}
	for _, resolved := range project.Members {
		data, ok := vendorSources[resolved.Vendor.ID]
		if !ok {
			return nil, nil, fmt.Errorf("missing signed vendor source %q", resolved.Vendor.ID)
		}
		expectedVendor, err := BuildVendor(resolved.Vendor)
		if err != nil {
			return nil, nil, err
		}
		authenticatedVendor, err := AuthenticateSource(data, sourceRoots, currentTime)
		if err != nil {
			return nil, nil, fmt.Errorf("vendor source %q: %w", resolved.Vendor.ID, err)
		}
		if err := authorizeSource(authenticatedVendor, resolved.Vendor.ID, signerScopes); err != nil {
			return nil, nil, err
		}
		if err := sameUnsignedCoRIM(expectedVendor, authenticatedVendor.Unsigned); err != nil {
			return nil, nil, fmt.Errorf("vendor source %q drift: %w", resolved.Vendor.ID, err)
		}
		provenance[resolved.Vendor.ID] = authenticatedVendor.Digest
		if authenticatedVendor.NotBefore.After(notBefore) {
			notBefore = authenticatedVendor.NotBefore
		}
		if authenticatedVendor.NotAfter.Before(notAfter) {
			notAfter = authenticatedVendor.NotAfter
		}
	}
	merged, err := BuildPlatform(project, true)
	if err != nil {
		return nil, nil, err
	}
	if !notAfter.After(notBefore) {
		return nil, nil, errors.New("source validity intersection is empty")
	}
	merged.SetRimValidity(notAfter, &notBefore)
	snapshot, err := SignDemoSnapshot(merged, snapshotPrivateKeyPEM, snapshotCertificatePEM, snapshotSigner)
	return snapshot, provenance, err
}

func authorizeSource(source *AuthenticatedSource, scope string, scopes map[string]string) error {
	digest := sha256.Sum256(source.SigningCertificate.Raw)
	if scopes[scope] != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("source signer is not authorized for scope %q", scope)
	}
	return nil
}

func sameUnsignedCoRIM(expected, actual *corim.UnsignedCorim) error {
	expectedCBOR, err := expected.ToCBOR()
	if err != nil {
		return err
	}
	actualCBOR, err := actual.ToCBOR()
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedCBOR, actualCBOR) {
		return errors.New("authenticated source does not match compiled reviewed manifest")
	}
	return nil
}

func sourceValidity(name string, validity *corim.Validity, currentTime time.Time) error {
	if validity == nil {
		return fmt.Errorf("%s has no validity", name)
	}
	if validity.NotBefore != nil && currentTime.Before(*validity.NotBefore) {
		return fmt.Errorf("%s is not yet valid", name)
	}
	if currentTime.After(validity.NotAfter) {
		return fmt.Errorf("%s is expired", name)
	}
	return nil
}
