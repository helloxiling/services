// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

const (
	cwtTag                = 61
	coseSign1Tag          = 18
	es384COSEAlgorithm    = -35
	eatContentType        = "application/eat+cwt"
	conciseEvidenceFormat = 10571
	claimNonce            = 10
	claimUEID             = 256
	claimProfile          = 265
	claimSubmods          = 266
	claimMeasurements     = 273
	headerAlgorithm       = 1
	headerContentType     = 3
	headerX5Chain         = 33
	headerX5Thumbprint    = 34
	CompositeEATProfile   = "tag:example.com,2026:composite-eat-reference#1.0.0"
)

type VerificationContext struct {
	Roots           *x509.CertPool
	CurrentTime     time.Time
	Nonce           []byte
	ExpectedProfile string
}

type LeadClaims struct {
	Nonce        []byte
	UEID         []byte
	Profile      string
	Measurements [][]byte
	Submods      map[string]DetachedDigest
	Leaf         *x509.Certificate
}

func VerifyMainToken(data []byte, context VerificationContext, limits Limits) (*LeadClaims, error) {
	if context.Roots == nil {
		return nil, errors.New("lead Attester roots are not configured")
	}
	if len(context.Nonce) != 32 {
		return nil, fmt.Errorf("expected challenge must be 32 bytes, got %d", len(context.Nonce))
	}
	if context.CurrentTime.IsZero() {
		context.CurrentTime = time.Now()
	}

	decMode, err := strictDecMode(limits)
	if err != nil {
		return nil, err
	}
	if err := requireCoreDeterministic(data, decMode); err != nil {
		return nil, fmt.Errorf("main-token encoding: %w", err)
	}

	var cwt cbor.RawTag
	if err := decMode.Unmarshal(data, &cwt); err != nil {
		return nil, fmt.Errorf("decode CWT: %w", err)
	}
	if cwt.Number != cwtTag {
		return nil, fmt.Errorf("unexpected main-token tag %d", cwt.Number)
	}
	var cose cbor.RawTag
	if err := decMode.Unmarshal(cwt.Content, &cose); err != nil {
		return nil, fmt.Errorf("decode COSE_Sign1 tag: %w", err)
	}
	if cose.Number != coseSign1Tag {
		return nil, fmt.Errorf("unexpected COSE tag %d", cose.Number)
	}

	var fields []cbor.RawMessage
	if err := decMode.Unmarshal(cose.Content, &fields); err != nil {
		return nil, fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	if len(fields) != 4 {
		return nil, fmt.Errorf("invalid COSE_Sign1 value: expected four fields, got %d", len(fields))
	}

	var protectedBytes, payload, signature []byte
	if err := decMode.Unmarshal(fields[0], &protectedBytes); err != nil {
		return nil, fmt.Errorf("decode protected headers: %w", err)
	}
	if err := decMode.Unmarshal(fields[2], &payload); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	if err := decMode.Unmarshal(fields[3], &signature); err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	thumbprint, err := parseProtectedHeaders(protectedBytes, decMode)
	if err != nil {
		return nil, err
	}
	chain, err := parseUnprotectedHeaders(fields[1], decMode)
	if err != nil {
		return nil, err
	}
	leaf, err := authenticateLeadChain(chain, context)
	if err != nil {
		return nil, err
	}
	actualThumbprint := sha512.Sum384(leaf.Raw)
	if !bytes.Equal(actualThumbprint[:], thumbprint) {
		return nil, errors.New("protected x5t does not match the x5chain leaf")
	}
	if err := verifyES384(leaf, protectedBytes, payload, signature); err != nil {
		return nil, err
	}

	claims, err := parseLeadClaims(payload, decMode, context.ExpectedProfile)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(claims.Nonce, context.Nonce) {
		return nil, errors.New("lead Attester nonce does not match the challenge")
	}
	claims.Leaf = leaf
	return claims, nil
}

func parseProtectedHeaders(data []byte, decMode cbor.DecMode) ([]byte, error) {
	if err := requireCoreDeterministic(data, decMode); err != nil {
		return nil, fmt.Errorf("protected headers: %w", err)
	}
	var headers map[int64]cbor.RawMessage
	if err := decMode.Unmarshal(data, &headers); err != nil {
		return nil, fmt.Errorf("decode protected header map: %w", err)
	}
	if len(headers) != 3 {
		return nil, errors.New("protected header map must contain exactly alg, content-type, and x5t")
	}
	var algorithm int64
	if err := decMode.Unmarshal(headers[headerAlgorithm], &algorithm); err != nil || algorithm != es384COSEAlgorithm {
		return nil, fmt.Errorf("protected alg must be %d", es384COSEAlgorithm)
	}
	var contentType string
	if err := decMode.Unmarshal(headers[headerContentType], &contentType); err != nil || contentType != eatContentType {
		return nil, fmt.Errorf("protected content-type must be %q", eatContentType)
	}
	var x5t []cbor.RawMessage
	if err := decMode.Unmarshal(headers[headerX5Thumbprint], &x5t); err != nil || len(x5t) != 2 {
		return nil, errors.New("protected x5t must be a two-element array")
	}
	var hashAlgorithm int64
	var thumbprint []byte
	if err := decMode.Unmarshal(x5t[0], &hashAlgorithm); err != nil || hashAlgorithm != sha384COSEAlgorithm {
		return nil, fmt.Errorf("protected x5t algorithm must be %d", sha384COSEAlgorithm)
	}
	if err := decMode.Unmarshal(x5t[1], &thumbprint); err != nil || len(thumbprint) != sha512.Size384 {
		return nil, fmt.Errorf("protected x5t digest must be %d bytes", sha512.Size384)
	}
	return thumbprint, nil
}

func parseUnprotectedHeaders(data []byte, decMode cbor.DecMode) ([]*x509.Certificate, error) {
	var headers map[int64]cbor.RawMessage
	if err := decMode.Unmarshal(data, &headers); err != nil {
		return nil, fmt.Errorf("decode unprotected header map: %w", err)
	}
	if len(headers) != 1 {
		return nil, errors.New("unprotected header map must contain exactly x5chain")
	}
	rawChain, ok := headers[headerX5Chain]
	if !ok {
		return nil, errors.New("unprotected x5chain is missing")
	}

	var single []byte
	var encodedChain [][]byte
	if err := decMode.Unmarshal(rawChain, &single); err == nil {
		encodedChain = [][]byte{single}
	} else if err := decMode.Unmarshal(rawChain, &encodedChain); err != nil {
		return nil, errors.New("x5chain must be a certificate byte string or array")
	}
	if len(encodedChain) == 0 || len(encodedChain) > 8 {
		return nil, fmt.Errorf("x5chain contains %d certificates", len(encodedChain))
	}

	chain := make([]*x509.Certificate, 0, len(encodedChain))
	for index, encoded := range encodedChain {
		cert, err := x509.ParseCertificate(encoded)
		if err != nil {
			return nil, fmt.Errorf("parse x5chain certificate %d: %w", index, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

func authenticateLeadChain(chain []*x509.Certificate, context VerificationContext) (*x509.Certificate, error) {
	leaf := chain[0]
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("lead Attester leaf certificate lacks digitalSignature usage")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         context.Roots,
		Intermediates: intermediates,
		CurrentTime:   context.CurrentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("validate Lead Attester certificate path: %w", err)
	}
	return leaf, nil
}

func parseLeadClaims(data []byte, decMode cbor.DecMode, expectedProfiles ...string) (*LeadClaims, error) {
	if err := requireCoreDeterministic(data, decMode); err != nil {
		return nil, fmt.Errorf("lead claims: %w", err)
	}
	var claims map[int64]cbor.RawMessage
	if err := decMode.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("decode Lead claims: %w", err)
	}
	if len(claims) != 5 {
		return nil, errors.New("lead claims closed map must contain exactly nonce, profile, UEID, measurements, and submods")
	}
	for _, key := range []int64{claimNonce, claimProfile, claimUEID, claimMeasurements, claimSubmods} {
		if _, ok := claims[key]; !ok {
			return nil, fmt.Errorf("lead claims missing key %d", key)
		}
	}

	var nonce, ueid []byte
	if err := decMode.Unmarshal(claims[claimNonce], &nonce); err != nil || len(nonce) != 32 {
		return nil, errors.New("lead nonce must be a 32-byte byte string")
	}
	if err := decMode.Unmarshal(claims[claimUEID], &ueid); err != nil || len(ueid) < 7 || len(ueid) > 33 {
		return nil, errors.New("lead UEID must be a 7-to-33-byte byte string")
	}
	profile, err := parseCompositeProfile(claims[claimProfile], decMode, expectedProfiles...)
	if err != nil {
		return nil, err
	}
	measurements, err := parseLeadMeasurements(claims[claimMeasurements], decMode)
	if err != nil {
		return nil, err
	}
	submods, err := parseSubmods(claims[claimSubmods], decMode)
	if err != nil {
		return nil, err
	}
	return &LeadClaims{Nonce: nonce, UEID: ueid, Profile: profile, Measurements: measurements, Submods: submods}, nil
}

func parseCompositeProfile(data []byte, decMode cbor.DecMode, expectedProfiles ...string) (string, error) {
	var profile string
	if err := decMode.Unmarshal(data, &profile); err != nil {
		return "", errors.New("composite EAT profile must be a URI string")
	}
	expected := CompositeEATProfile
	if len(expectedProfiles) != 0 && expectedProfiles[0] != "" {
		expected = expectedProfiles[0]
	}
	if err := manifest.ValidateProfileURI(expected); err != nil {
		return "", err
	}
	if profile != expected {
		return "", fmt.Errorf("composite EAT profile %q is not enabled", profile)
	}
	return profile, nil
}

func parseLeadMeasurements(data []byte, decMode cbor.DecMode) ([][]byte, error) {
	var entries []cbor.RawMessage
	if err := decMode.Unmarshal(data, &entries); err != nil || len(entries) == 0 {
		return nil, errors.New("lead measurements must be a non-empty array")
	}
	measurements := make([][]byte, 0, len(entries))
	for index, entry := range entries {
		var pair []cbor.RawMessage
		if err := decMode.Unmarshal(entry, &pair); err != nil || len(pair) != 2 {
			return nil, fmt.Errorf("lead measurement %d must be a two-element array", index)
		}
		var contentFormat uint64
		var value []byte
		if err := decMode.Unmarshal(pair[0], &contentFormat); err != nil || contentFormat != conciseEvidenceFormat {
			return nil, fmt.Errorf("lead measurement %d content-format must be %d", index, conciseEvidenceFormat)
		}
		if err := decMode.Unmarshal(pair[1], &value); err != nil || len(value) == 0 {
			return nil, fmt.Errorf("lead measurement %d value must be a non-empty byte string", index)
		}
		measurements = append(measurements, value)
	}
	return measurements, nil
}

func parseSubmods(data []byte, decMode cbor.DecMode) (map[string]DetachedDigest, error) {
	var raw map[string]cbor.RawMessage
	if err := decMode.Unmarshal(data, &raw); err != nil || len(raw) == 0 {
		return nil, errors.New("submods must be a non-empty map")
	}
	result := make(map[string]DetachedDigest, len(raw))
	for environmentID, encoded := range raw {
		if err := validateEnvironmentID(environmentID); err != nil {
			return nil, err
		}
		var pair []cbor.RawMessage
		if err := decMode.Unmarshal(encoded, &pair); err != nil || len(pair) != 2 {
			return nil, fmt.Errorf("submods[%q] must be a two-element digest array", environmentID)
		}
		var digest DetachedDigest
		if err := decMode.Unmarshal(pair[0], &digest.Algorithm); err != nil {
			return nil, fmt.Errorf("decode submods[%q] algorithm: %w", environmentID, err)
		}
		if err := decMode.Unmarshal(pair[1], &digest.Value); err != nil {
			return nil, fmt.Errorf("decode submods[%q] digest: %w", environmentID, err)
		}
		result[environmentID] = digest
	}
	return result, nil
}

func verifyES384(leaf *x509.Certificate, protected, payload, signature []byte) error {
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != "P-384" {
		return errors.New("lead Attester signing key must be ECDSA P-384")
	}
	if len(signature) != 96 {
		return fmt.Errorf("invalid ES384 signature value: expected 96 bytes, got %d", len(signature))
	}
	toBeSigned, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return err
	}
	sigStructure, err := toBeSigned.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return fmt.Errorf("encode COSE Sig_structure: %w", err)
	}
	digest := sha512.Sum384(sigStructure)
	r := new(big.Int).SetBytes(signature[:48])
	s := new(big.Int).SetBytes(signature[48:])
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return errors.New("lead Attester ES384 signature verification failed")
	}
	return nil
}
