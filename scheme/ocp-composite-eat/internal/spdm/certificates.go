// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package spdm

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
)

func parseCertificateChain(data []byte, limits Limits) ([]*x509.Certificate, error) {
	if len(data) == 0 || len(data) > limits.MaxCertificateChainBytes {
		return nil, verificationError(ErrorCertificate, "certificate chain size is invalid")
	}
	var certificates []*x509.Certificate
	for offset := 0; offset < len(data); {
		length, err := derObjectLength(data[offset:])
		if err != nil {
			return nil, verificationError(ErrorCertificate, "certificate %d: %v", len(certificates), err)
		}
		if length > limits.MaxCertificateBytes || offset+length > len(data) {
			return nil, verificationError(ErrorCertificate, "certificate %d exceeds configured bounds", len(certificates))
		}
		certificate, err := x509.ParseCertificate(data[offset : offset+length])
		if err != nil {
			return nil, verificationError(ErrorCertificate, "parse certificate %d: %v", len(certificates), err)
		}
		certificates = append(certificates, certificate)
		if len(certificates) > limits.MaxCertificates {
			return nil, verificationError(ErrorCertificate, "certificate count exceeds %d", limits.MaxCertificates)
		}
		offset += length
	}
	return certificates, nil
}

func derObjectLength(data []byte) (int, error) {
	if len(data) < 2 || data[0] != 0x30 {
		return 0, errors.New("expected DER SEQUENCE")
	}
	if data[1]&0x80 == 0 {
		return 2 + int(data[1]), nil
	}
	lengthBytes := int(data[1] & 0x7f)
	if lengthBytes == 0 || lengthBytes > 4 || len(data) < 2+lengthBytes {
		return 0, errors.New("invalid DER length")
	}
	if data[2] == 0 {
		return 0, errors.New("non-minimal DER length")
	}
	var contentLength uint32
	for _, value := range data[2 : 2+lengthBytes] {
		contentLength = contentLength<<8 | uint32(value)
	}
	if contentLength < 128 {
		return 0, errors.New("non-minimal DER long-form length")
	}
	total := uint64(2+lengthBytes) + uint64(contentLength)
	if total > uint64(len(data)) || total > uint64(^uint(0)>>1) {
		return 0, errors.New("truncated DER object")
	}
	return int(total), nil
}

func verifyChainSignatures(certificates []*x509.Certificate) error {
	if len(certificates) == 0 {
		return errors.New("certificate chain is empty")
	}
	for index := 1; index < len(certificates); index++ {
		parent := certificates[index-1]
		child := certificates[index]
		if err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
			return fmt.Errorf("certificate %d is not signed by certificate %d: %w", index, index-1, err)
		}
	}
	return nil
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}
