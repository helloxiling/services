// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestVerifyMainToken(t *testing.T) {
	fixture := newMainTokenFixture(t)
	claims, err := VerifyMainToken(fixture.token, VerificationContext{
		Roots: fixture.roots, CurrentTime: fixture.now, Nonce: fixture.nonce,
	}, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, fixture.nonce, claims.Nonce)
	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, claims.UEID)
	require.Equal(t, CompositeEATProfile, claims.Profile)
	require.Contains(t, claims.Submods, "env.device.0")
}

func TestVerifyMainTokenRejectsPendingOCPProfile(t *testing.T) {
	fixture := newMainTokenFixtureWithProfile(t, cbor.Tag{
		Number:  112,
		Content: []byte{0x82, 0xcc, 0x7f, 0x01, 0x04},
	})
	_, err := VerifyMainToken(fixture.token, VerificationContext{
		Roots: fixture.roots, CurrentTime: fixture.now, Nonce: fixture.nonce,
	}, DefaultLimits())
	require.ErrorContains(t, err, "profile must be a URI string")
}

func TestVerifyMainTokenRejectsUnknownProfileWithoutFallback(t *testing.T) {
	fixture := newMainTokenFixtureWithProfile(t, "tag:example.com,2026:other-profile#1.0.0")
	_, err := VerifyMainToken(fixture.token, VerificationContext{
		Roots: fixture.roots, CurrentTime: fixture.now, Nonce: fixture.nonce,
	}, DefaultLimits())
	require.ErrorContains(t, err, "is not enabled")
}

func TestExplicitProfileRequiresExactConfiguration(t *testing.T) {
	profile := "tag:example.com,2026:strict-composite-contract-v1"
	fixture := newMainTokenFixtureWithProfile(t, profile)
	context := VerificationContext{Roots: fixture.roots, CurrentTime: fixture.now, Nonce: fixture.nonce, ExpectedProfile: profile}
	claims, err := VerifyMainToken(fixture.token, context, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, profile, claims.Profile)
	context.ExpectedProfile = CompositeEATProfile
	_, err = VerifyMainToken(fixture.token, context, DefaultLimits())
	require.ErrorContains(t, err, "is not enabled")
}

func TestVerifyMainTokenRejectsNonceMismatch(t *testing.T) {
	fixture := newMainTokenFixture(t)
	_, err := VerifyMainToken(fixture.token, VerificationContext{
		Roots: fixture.roots, CurrentTime: fixture.now, Nonce: make([]byte, 32),
	}, DefaultLimits())
	require.ErrorContains(t, err, "nonce does not match")
}

func TestVerifyMainTokenRejectsUntrustedSigner(t *testing.T) {
	fixture := newMainTokenFixture(t)
	_, err := VerifyMainToken(fixture.token, VerificationContext{
		Roots: x509.NewCertPool(), CurrentTime: fixture.now, Nonce: fixture.nonce,
	}, DefaultLimits())
	require.ErrorContains(t, err, "certificate path")
}

func TestVerifyMainTokenRejectsSignatureMutation(t *testing.T) {
	fixture := newMainTokenFixture(t)
	mutated := append([]byte(nil), fixture.token...)
	mutated[len(mutated)-1] ^= 1
	_, err := VerifyMainToken(mutated, VerificationContext{
		Roots: fixture.roots, CurrentTime: fixture.now, Nonce: fixture.nonce,
	}, DefaultLimits())
	require.Error(t, err)
}

type mainTokenFixture struct {
	token []byte
	nonce []byte
	roots *x509.CertPool
	now   time.Time
}

func newMainTokenFixture(t *testing.T) mainTokenFixture {
	return newMainTokenFixtureWithProfile(t, CompositeEATProfile)
}

func newMainTokenFixtureWithProfile(t *testing.T, profile any) mainTokenFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	rootKey, rootDER, root := makeCertificate(t, nil, nil, true, "Test Root", now)
	leafKey, leafDER, _ := makeCertificate(t, root, rootKey, false, "Lead Attester", now)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	nonce := make([]byte, 32)
	for index := range nonce {
		nonce[index] = byte(index)
	}
	claimsSet := mustEncode(t, map[int64]any{cmwClaim: []any{"application/eat+cwt", []byte{0x01}, uint64(4)}})
	detachedDigest := sha512.Sum384(claimsSet)
	payload := mustEncode(t, map[int64]any{
		claimNonce:        nonce,
		claimUEID:         []byte{1, 2, 3, 4, 5, 6, 7},
		claimProfile:      profile,
		claimSubmods:      map[string]any{"env.device.0": []any{int64(sha384COSEAlgorithm), detachedDigest[:]}},
		claimMeasurements: []any{[]any{uint64(conciseEvidenceFormat), []byte{0xa1, 0x00, 0xa0}}},
	})
	leafThumbprint := sha512.Sum384(leafDER)
	protected := mustEncode(t, map[int64]any{
		headerAlgorithm:    int64(es384COSEAlgorithm),
		headerContentType:  eatContentType,
		headerX5Thumbprint: []any{int64(sha384COSEAlgorithm), leafThumbprint[:]},
	})
	sigStructure := mustEncode(t, []any{"Signature1", protected, []byte{}, payload})
	hash := sha512.Sum384(sigStructure)
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, hash[:])
	require.NoError(t, err)
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])

	token := mustEncode(t, cbor.Tag{Number: cwtTag, Content: cbor.Tag{
		Number: coseSign1Tag,
		Content: []any{
			protected,
			map[int64]any{headerX5Chain: []any{leafDER, rootDER}},
			payload,
			signature,
		},
	}})
	return mainTokenFixture{token: token, nonce: nonce, roots: roots, now: now}
}

func makeCertificate(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	isCA bool,
	commonName string,
	now time.Time,
) (*ecdsa.PrivateKey, []byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
		issuer = template
		issuerKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, der, cert
}
