// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package spdm

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
)

const (
	spdm12SigningPrefix = "dmtf-spdm-v1.2.*"
	measurementsContext = "responder-measurements signing"
	combinedPrefixSize  = 100
)

func transcriptDigest(version Version, algorithm BaseHashAlgorithm, transcript []byte) ([]byte, error) {
	first, err := hashBytes(algorithm, transcript)
	if err != nil {
		return nil, err
	}
	if version < Version12 {
		return first, nil
	}
	context := make([]byte, 0, combinedPrefixSize+len(first))
	for range 4 {
		context = append(context, spdm12SigningPrefix...)
	}
	context = append(context, 0)
	padding := combinedPrefixSize - len(context) - len(measurementsContext)
	if padding < 0 {
		return nil, errors.New("SPDM signing context exceeds fixed prefix")
	}
	context = append(context, make([]byte, padding)...)
	context = append(context, measurementsContext...)
	context = append(context, first...)
	return hashBytes(algorithm, context)
}

func hashBytes(algorithm BaseHashAlgorithm, data []byte) ([]byte, error) {
	switch algorithm {
	case BaseHashSHA256:
		digest := sha256.Sum256(data)
		return digest[:], nil
	case BaseHashSHA384:
		digest := sha512.Sum384(data)
		return digest[:], nil
	default:
		return nil, verificationError(ErrorUnsupported, "base hash %q", algorithm)
	}
}

func verifyECDSA(publicKey *ecdsa.PublicKey, digest, signature []byte, reverse bool) bool {
	componentSize := (publicKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != componentSize*2 {
		return false
	}
	rBytes := append([]byte(nil), signature[:componentSize]...)
	sBytes := append([]byte(nil), signature[componentSize:]...)
	if reverse {
		reverseBytes(rBytes)
		reverseBytes(sBytes)
	}
	return ecdsa.Verify(publicKey, digest, new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes))
}

func reverseBytes(value []byte) {
	for left, right := 0, len(value)-1; left < right; left, right = left+1, right-1 {
		value[left], value[right] = value[right], value[left]
	}
}
