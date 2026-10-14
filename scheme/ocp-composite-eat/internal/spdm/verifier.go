// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package spdm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"time"
)

type Verifier interface {
	Verify(context.Context, Evidence, Policy) (*Result, error)
}

type ExperimentalVerifier struct {
	Limits Limits
}

func NewExperimentalVerifier() *ExperimentalVerifier {
	return &ExperimentalVerifier{Limits: DefaultLimits()}
}

func (v *ExperimentalVerifier) Verify(ctx context.Context, evidence Evidence, policy Policy) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(policy.ExpectedNonce) != 32 {
		return nil, verificationError(ErrorPolicy, "expected nonce must be 32 bytes")
	}
	parsed, err := parseSignedMeasurements(evidence, v.Limits)
	if err != nil {
		return nil, err
	}
	if (parsed.algorithms.version == Version10 && !policy.AllowSPDM10) ||
		(parsed.algorithms.version == Version12 && !policy.AllowSPDM12) ||
		parsed.algorithms.version == Version11 {
		return nil, verificationError(ErrorUnsupported, "SPDM version %s is not enabled", parsed.algorithms.version)
	}
	if !contains(policy.AllowedBaseHashes, parsed.algorithms.baseHash) || !contains(policy.AllowedBaseAsym, parsed.algorithms.baseAsym) {
		return nil, verificationError(ErrorPolicy, "negotiated algorithms are not allowed")
	}
	certificates, err := parseCertificateChain(evidence.CertificateChainDER, v.Limits)
	if err != nil {
		return nil, err
	}
	if err := verifyChainSignatures(certificates); err != nil {
		return nil, verificationError(ErrorCertificate, "%v", err)
	}
	leaf := certificates[len(certificates)-1]
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, verificationError(ErrorCertificate, "leaf certificate lacks digitalSignature usage")
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || (parsed.algorithms.baseAsym == BaseAsymECDSAP256 && publicKey.Curve.Params().BitSize != 256) ||
		(parsed.algorithms.baseAsym == BaseAsymECDSAP384 && publicKey.Curve.Params().BitSize != 384) {
		return nil, verificationError(ErrorCertificate, "leaf key does not match negotiated base asymmetric algorithm")
	}
	digest, err := transcriptDigest(parsed.algorithms.version, parsed.algorithms.baseHash, parsed.transcript)
	if err != nil {
		return nil, err
	}
	encoding := SignatureEncodingBigEndian
	if !verifyECDSA(publicKey, digest, parsed.signature, false) {
		if parsed.algorithms.version != Version10 || !policy.AllowSPDM10ReversedECDSA || !verifyECDSA(publicKey, digest, parsed.signature, true) {
			return nil, verificationError(ErrorSignature, "SPDM measurement signature verification failed")
		}
		encoding = SignatureEncodingLegacyReversed
	}

	result := &Result{
		Version: parsed.algorithms.version, BaseHash: parsed.algorithms.baseHash,
		BaseAsym: parsed.algorithms.baseAsym, MeasurementHash: parsed.algorithms.measurementHash,
		RequesterNonce: parsed.requesterNonce, ResponderNonce: parsed.responderNonce,
		Slot: parsed.slot, Leaf: leaf, CertificateChain: certificates,
		TranscriptDigest: digest, VCAAuthenticated: parsed.algorithms.version >= Version12,
		SignatureEncoding: encoding, ChainSignaturesValid: true,
		IdentityAuthorization: OutcomeIndeterminate, RootTrust: OutcomeIndeterminate,
		Measurements: parsed.measurements,
	}
	if len(policy.AuthorizedLeafKeys) > 0 {
		result.IdentityAuthorization = OutcomeFail
		for _, key := range policy.AuthorizedLeafKeys {
			if publicKeysEqual(key, leaf.PublicKey) {
				result.IdentityAuthorization = OutcomePass
				break
			}
		}
	}
	if policy.Roots != nil {
		result.RootTrust = OutcomeFail
		intermediates := x509.NewCertPool()
		if len(certificates) > 2 {
			for _, certificate := range certificates[1 : len(certificates)-1] {
				intermediates.AddCert(certificate)
			}
		}
		currentTime := policy.CurrentTime
		if currentTime.IsZero() {
			currentTime = time.Now()
		}
		if _, verifyErr := leaf.Verify(x509.VerifyOptions{
			Roots: policy.Roots, Intermediates: intermediates, CurrentTime: currentTime,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); verifyErr == nil {
			result.RootTrust = OutcomePass
		}
	}
	if !bytes.Equal(parsed.requesterNonce, policy.ExpectedNonce) {
		return result, verificationError(ErrorFreshness, "requester nonce does not match expected challenge")
	}
	compatibilityUsed, err := validateMeasurementSemantics(parsed.algorithms.version, result.Measurements, policy.MeasurementTypePolicy)
	result.MeasurementTypeCompatibilityUsed = compatibilityUsed
	if err != nil {
		return result, err
	}
	return result, nil
}

func validateMeasurementSemantics(version Version, blocks []MeasurementBlock, policy MeasurementTypePolicy) (bool, error) {
	if policy == "" {
		policy = MeasurementTypePolicyVersionStrict
	}
	if policy != MeasurementTypePolicyVersionStrict && policy != MeasurementTypePolicyKnownTypes {
		return false, verificationError(ErrorPolicy, "unsupported SPDM measurement-type policy %q", policy)
	}
	maxType := MeasurementTypeFirmwareSVN
	if version >= Version13 {
		maxType = MeasurementTypeStructuredManifest
	}
	compatibilityUsed := false
	for _, block := range blocks {
		if block.MeasurementSpecification != measurementSpecificationDMTF {
			return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index %d uses unsupported specification %d", block.Index, block.MeasurementSpecification)
		}
		if block.ValueType > MeasurementTypeStructuredManifest {
			return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index %d uses unknown type %d", block.Index, block.ValueType)
		}
		if block.ValueType > maxType {
			if policy != MeasurementTypePolicyKnownTypes {
				return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index %d uses type %d, reserved in SPDM %s", block.Index, block.ValueType, version)
			}
			compatibilityUsed = true
		}
		if block.ValueType == MeasurementTypeDeviceMode && !block.RawBitStream {
			return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index %d device-mode type must use raw-bit-stream representation", block.Index)
		}
		if block.ValueType == MeasurementTypeHashExtend && block.RawBitStream {
			return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index %d hash-extend type must use digest representation", block.Index)
		}
		if block.ValueType == MeasurementTypeInformational && !block.RawBitStream {
			return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index %d informational type must use raw-bit-stream representation", block.Index)
		}
		switch {
		case block.Index == 0 || block.Index == 0xff:
			return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index 0x%02x is not valid in a measurement block", block.Index)
		case block.Index >= 0xf0 && block.Index <= 0xfc:
			return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index 0x%02x is reserved", block.Index)
		case block.Index == 0xfd:
			if block.ValueType != MeasurementTypeManifest && block.ValueType != MeasurementTypeStructuredManifest {
				return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index 0xfd must contain a measurement manifest")
			}
		case block.Index == 0xfe && block.ValueType != MeasurementTypeDeviceMode:
			return compatibilityUsed, verificationError(ErrorUnsupported, "measurement index 0xfe must contain device-mode data")
		}
	}
	return compatibilityUsed, nil
}

func contains[T comparable](values []T, expected T) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

var _ Verifier = (*ExperimentalVerifier)(nil)
