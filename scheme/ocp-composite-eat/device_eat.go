// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"crypto/x509"
	"encoding/asn1"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/corim/coev"
	"github.com/veraison/corim/comid"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
	"time"
)

const (
	cborSelfDescribeTag = 55799
	claimDebugStatus    = 263
	headerKeyID         = 4
	oidTag              = 111
	deviceEATProfile    = "1.3.6.1.4.1.42623.1.3"
)

type DeviceClaims struct {
	KeyID           []byte
	DebugStatus     uint64
	EvidenceTriples []comid.ValueTriple
	SigningKey      crypto.PublicKey
}

type MeasurementAppraisal struct {
	Passed     bool
	Reason     string
	Unresolved Outcome
}

func (a MeasurementAppraisal) dimension() DimensionResult {
	status := OutcomeFail
	if a.Passed {
		status = OutcomePass
	} else if a.Unresolved != "" {
		status = a.Unresolved
	}
	return DimensionResult{Status: status, Reason: a.Reason}
}

func ExtractDeviceEAT(claimsSet []byte, limits Limits) ([]byte, error) {
	decoded, err := DecodeNativeEvidence(claimsSet, "cmw-encoding", eatContentType, limits)
	if err != nil {
		return nil, fmt.Errorf("device EAT CMW: %w", err)
	}
	return decoded.DeviceEAT, nil
}

func VerifyCaliptraDeviceEAT(
	data []byte,
	nonce []byte,
	expectation MemberExpectation,
	limits Limits,
) (*DeviceClaims, error) {
	if len(data) > 64*1024 {
		return nil, errors.New("device EAT exceeds 64-KiB limit")
	}
	if len(nonce) != 32 {
		return nil, fmt.Errorf("expected device EAT challenge must be 32 bytes, got %d", len(nonce))
	}
	decMode, err := strictDecMode(limits)
	if err != nil {
		return nil, err
	}
	coseContent, err := unwrapTags(data, decMode, cborSelfDescribeTag, cwtTag, coseSign1Tag)
	if err != nil {
		return nil, err
	}
	if err := requireCoreDeterministic(coseContent, decMode); err != nil {
		return nil, fmt.Errorf("device EAT COSE encoding: %w", err)
	}
	var fields []cbor.RawMessage
	if err := decMode.Unmarshal(coseContent, &fields); err != nil || len(fields) != 4 {
		return nil, errors.New("device EAT COSE_Sign1 must contain four fields")
	}
	var protected, payload, signature []byte
	if err := decMode.Unmarshal(fields[0], &protected); err != nil {
		return nil, fmt.Errorf("decode Device EAT protected headers: %w", err)
	}
	if err := decMode.Unmarshal(fields[2], &payload); err != nil {
		return nil, fmt.Errorf("decode Device EAT payload: %w", err)
	}
	if err := decMode.Unmarshal(fields[3], &signature); err != nil {
		return nil, fmt.Errorf("decode Device EAT signature: %w", err)
	}
	if err := validateCaliptraProtectedHeaders(protected, decMode); err != nil {
		return nil, err
	}
	keyID, err := parseCaliptraKeyID(fields[1], decMode)
	if err != nil {
		return nil, err
	}
	claims, err := parseDeviceClaims(payload, nonce, decMode)
	if err != nil {
		return nil, err
	}
	key, err := verifyWithAuthorizedKey(expectation.IdentityKeys, protected, payload, signature)
	if err != nil {
		return nil, err
	}
	claims.KeyID = keyID
	claims.SigningKey = key
	return claims, nil
}

func AppraiseMeasurements(referenceValues, evidenceValues []comid.ValueTriple) MeasurementAppraisal {
	if len(referenceValues) == 0 {
		return MeasurementAppraisal{Unresolved: OutcomeIndeterminate, Reason: "reference values are missing"}
	}
	for referenceIndex := range referenceValues {
		reference := &referenceValues[referenceIndex]
		var evidence []comid.Measurement
		for evidenceIndex := range evidenceValues {
			candidate := &evidenceValues[evidenceIndex]
			if reflect.DeepEqual(reference.Environment, candidate.Environment) {
				evidence = append(evidence, candidate.Measurements.Values...)
			}
		}
		if evidence == nil {
			return MeasurementAppraisal{Reason: fmt.Sprintf("no evidence for reference environment %d", referenceIndex)}
		}
		if result := matchMeasurements(reference.Measurements.Values, evidence); !result.Passed {
			return result
		}
	}
	return MeasurementAppraisal{Passed: true, Reason: "all required reference values matched"}
}

func parseDeviceClaims(data, nonce []byte, decMode cbor.DecMode, profileChecks ...func([]byte, cbor.DecMode) error) (*DeviceClaims, error) {
	if err := requireCoreDeterministic(data, decMode); err != nil {
		return nil, fmt.Errorf("device EAT claims: %w", err)
	}
	var claims map[int64]cbor.RawMessage
	if err := decMode.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("decode Device EAT claims: %w", err)
	}
	for _, key := range []int64{claimNonce, claimDebugStatus, claimProfile, claimMeasurements} {
		if _, ok := claims[key]; !ok {
			return nil, fmt.Errorf("device EAT missing mandatory claim %d", key)
		}
	}
	var tokenNonce []byte
	if err := decMode.Unmarshal(claims[claimNonce], &tokenNonce); err != nil || !bytes.Equal(tokenNonce, nonce) {
		return nil, errors.New("device EAT nonce does not match the challenge")
	}
	var debugStatus uint64
	if err := decMode.Unmarshal(claims[claimDebugStatus], &debugStatus); err != nil || debugStatus > 4 {
		return nil, errors.New("device EAT debug status is invalid")
	}
	if debugStatus == 0 {
		return nil, errors.New("device EAT reports debug enabled")
	}
	profileCheck := validateDeviceProfile
	if len(profileChecks) != 0 {
		profileCheck = profileChecks[0]
	}
	if err := profileCheck(claims[claimProfile], decMode); err != nil {
		return nil, err
	}
	triples, err := parseDeviceMeasurements(claims[claimMeasurements], decMode)
	if err != nil {
		return nil, err
	}
	return &DeviceClaims{DebugStatus: debugStatus, EvidenceTriples: triples}, nil
}

func validateDeviceProfile(data []byte, decMode cbor.DecMode) error {
	var tagged cbor.RawTag
	if err := decMode.Unmarshal(data, &tagged); err != nil || tagged.Number != oidTag {
		return fmt.Errorf("device EAT profile must use CBOR tag %d", oidTag)
	}
	var profile []byte
	if err := decMode.Unmarshal(tagged.Content, &profile); err != nil || string(profile) != deviceEATProfile {
		return errors.New("device EAT profile does not match OCP .1.3 Caliptra encoding")
	}
	return nil
}

func parseDeviceMeasurements(data []byte, decMode cbor.DecMode) ([]comid.ValueTriple, error) {
	var entries []cbor.RawMessage
	if err := decMode.Unmarshal(data, &entries); err != nil || len(entries) == 0 {
		return nil, errors.New("device EAT measurements must be a non-empty array")
	}
	var result []comid.ValueTriple
	for index, entry := range entries {
		var pair []cbor.RawMessage
		if err := decMode.Unmarshal(entry, &pair); err != nil || len(pair) != 2 {
			return nil, fmt.Errorf("device EAT measurement %d must be a two-element array", index)
		}
		var contentFormat uint64
		var encoded []byte
		if err := decMode.Unmarshal(pair[0], &contentFormat); err != nil || contentFormat != conciseEvidenceFormat {
			return nil, fmt.Errorf("device EAT measurement %d content-format must be %d", index, conciseEvidenceFormat)
		}
		if err := decMode.Unmarshal(pair[1], &encoded); err != nil {
			return nil, fmt.Errorf("decode Device EAT measurement %d: %w", index, err)
		}
		var tagged coev.TaggedConciseEvidence
		if err := tagged.FromCBOR(encoded); err != nil {
			return nil, fmt.Errorf("decode Device EAT Concise Evidence %d: %w", index, err)
		}
		concise := coev.ConciseEvidence(tagged)
		if concise.EvTriples.EvidenceTriples == nil {
			return nil, fmt.Errorf("device EAT Concise Evidence %d has no evidence triples", index)
		}
		result = append(result, concise.EvTriples.EvidenceTriples.Values...)
	}
	return result, nil
}

func validateCaliptraProtectedHeaders(data []byte, decMode cbor.DecMode) error {
	if err := requireCoreDeterministic(data, decMode); err != nil {
		return fmt.Errorf("legacy device EAT protected headers: %w", err)
	}
	var headers map[int64]int64
	if err := decMode.Unmarshal(data, &headers); err != nil || len(headers) != 1 || headers[headerAlgorithm] != es384COSEAlgorithm {
		return fmt.Errorf("legacy device EAT protected headers must be exactly {1: %d}", es384COSEAlgorithm)
	}
	return nil
}

func parseCaliptraKeyID(data []byte, decMode cbor.DecMode) ([]byte, error) {
	if err := requireCoreDeterministic(data, decMode); err != nil {
		return nil, fmt.Errorf("legacy device EAT unprotected headers: %w", err)
	}
	var headers map[int64][]byte
	if err := decMode.Unmarshal(data, &headers); err != nil || len(headers) != 1 {
		return nil, errors.New("legacy device EAT unprotected headers must contain exactly kid")
	}
	keyID, ok := headers[headerKeyID]
	if !ok || len(keyID) != 48 {
		return nil, errors.New("legacy device EAT kid must be 48 bytes")
	}
	return keyID, nil
}

func verifyWithAuthorizedKey(keys []crypto.PublicKey, protected, payload, signature []byte) (crypto.PublicKey, error) {
	if len(signature) != 96 {
		return nil, fmt.Errorf("device EAT ES384 signature must be 96 bytes, got %d", len(signature))
	}
	encMode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	sigStructure, err := encMode.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nil, err
	}
	digest := sha512.Sum384(sigStructure)
	r := new(big.Int).SetBytes(signature[:48])
	s := new(big.Int).SetBytes(signature[48:])
	for _, key := range keys {
		publicKey, ok := key.(*ecdsa.PublicKey)
		if ok && publicKey.Curve.Params().Name == "P-384" && ecdsa.Verify(publicKey, digest[:], r, s) {
			return key, nil
		}
	}
	return nil, errors.New("device EAT signature does not match an authorized identity key")
}

func unwrapTags(data []byte, decMode cbor.DecMode, tags ...uint64) ([]byte, error) {
	current := cbor.RawMessage(data)
	for _, expected := range tags {
		if expected == cborSelfDescribeTag {
			prefix := []byte{0xd9, 0xd9, 0xf7}
			if !bytes.HasPrefix(current, prefix) {
				return nil, fmt.Errorf("missing CBOR self-described tag %d", expected)
			}
			current = current[len(prefix):]
			continue
		}
		var tagged cbor.RawTag
		if err := decMode.Unmarshal(current, &tagged); err != nil {
			return nil, fmt.Errorf("decode expected CBOR tag %d: %w", expected, err)
		}
		if tagged.Number != expected {
			return nil, fmt.Errorf("unexpected CBOR tag %d, want %d", tagged.Number, expected)
		}
		current = tagged.Content
	}
	return current, nil
}

func matchMeasurements(reference, evidence []comid.Measurement) MeasurementAppraisal {
	if len(reference) == 0 {
		return MeasurementAppraisal{Unresolved: OutcomeIndeterminate, Reason: "reference measurements are empty"}
	}
	for _, required := range reference {
		key := measurementKey(required)
		encoded, err := json.Marshal(required.Val)
		if err != nil {
			return MeasurementAppraisal{Unresolved: OutcomeUnsupported, Reason: "cannot inspect reference constraints"}
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			return MeasurementAppraisal{Unresolved: OutcomeUnsupported, Reason: "invalid reference constraints"}
		}
		for field := range fields {
			if field != "digests" && field != "raw-value" && field != "raw-value-mask" && field != "flags" && field != "name" {
				return MeasurementAppraisal{Unresolved: OutcomeUnsupported, Reason: fmt.Sprintf("measurement %q uses unsupported constraint %q", key, field)}
			}
		}
		var observed *comid.Measurement
		for index := range evidence {
			if reflect.DeepEqual(evidence[index].Key, required.Key) {
				if observed != nil {
					return MeasurementAppraisal{Reason: fmt.Sprintf("duplicate measurement %q", key)}
				}
				observed = &evidence[index]
			}
		}
		if observed == nil {
			return MeasurementAppraisal{Reason: fmt.Sprintf("missing measurement %q", key)}
		}
		if required.Val.Name != nil && (observed.Val.Name == nil || *observed.Val.Name != *required.Val.Name) {
			return MeasurementAppraisal{Reason: fmt.Sprintf("measurement %q type mismatch", key)}
		}
		if required.Val.Flags != nil {
			var expectedFlags map[string]bool
			if err := json.Unmarshal(fields["flags"], &expectedFlags); err != nil {
				return MeasurementAppraisal{Unresolved: OutcomeUnsupported, Reason: "invalid reference flags"}
			}
			if _, err := manifest.BuildFlags(expectedFlags); err != nil {
				return MeasurementAppraisal{Unresolved: OutcomeUnsupported, Reason: err.Error()}
			}
			observedJSON, err := json.Marshal(observed.Val.Flags)
			var observedFlags map[string]bool
			if err != nil || json.Unmarshal(observedJSON, &observedFlags) != nil {
				return MeasurementAppraisal{Reason: "invalid observed flags"}
			}
			for flag, expected := range expectedFlags {
				actual, present := observedFlags[flag]
				if !present || actual != expected {
					return MeasurementAppraisal{Reason: fmt.Sprintf("measurement %q flag %q mismatch or absent", key, flag)}
				}
			}
		}
		if required.Val.Digests != nil {
			if observed.Val.Digests == nil || !normalizedDigests(*observed.Val.Digests).CompareAgainstReference(normalizedDigests(*required.Val.Digests)) {
				return MeasurementAppraisal{Reason: fmt.Sprintf("measurement %q digest mismatch", key)}
			}
		}
		if required.Val.RawValue != nil {
			var mask []byte
			if required.Val.RawValueMask != nil {
				mask = *required.Val.RawValueMask
			}
			if observed.Val.RawValue == nil || !observed.Val.RawValue.CompareAgainstReference(required.Val.RawValue.Bytes(), mask) {
				return MeasurementAppraisal{Reason: fmt.Sprintf("measurement %q raw value mismatch", key)}
			}
		}
		if required.Val.Digests == nil && required.Val.RawValue == nil {
			return MeasurementAppraisal{Unresolved: OutcomeUnsupported, Reason: fmt.Sprintf("measurement %q uses unsupported reference semantics", key)}
		}
	}
	return MeasurementAppraisal{Passed: true, Reason: "required measurements matched"}
}

func normalizedDigests(values comid.Digests) comid.Digests {
	result := append(comid.Digests(nil), values...)
	for index := range result {
		algorithm := result[index].Algorithm
		switch algorithm.String() {
		case "sha-256", "sha-384", "sha-512":
			result[index].Algorithm = comid.IntDigestAlgorithm(algorithm.Int())
		}
	}
	return result
}

func strictDeviceProfile(data []byte, mode cbor.DecMode) error {
	var value []byte
	if err := mode.Unmarshal(data, &value); err != nil {
		return errors.New("strict Device EAT profile must be an untagged OID byte string")
	}
	expected, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42623, 1, 3})
	if err != nil || !bytes.Equal(value, expected[2:]) {
		return errors.New("strict Device EAT profile OID mismatch")
	}
	return nil
}

func VerifyStrictDeviceEAT(data, nonce []byte, expectation MemberExpectation, now time.Time, limits Limits) (*DeviceClaims, error) {
	if len(data) > 64*1024 || len(nonce) != 32 {
		return nil, errors.New("invalid strict Device EAT size or nonce")
	}
	mode, err := strictDecMode(limits)
	if err != nil {
		return nil, err
	}
	content, err := unwrapTags(data, mode, cborSelfDescribeTag, cwtTag, coseSign1Tag)
	if err != nil {
		return nil, err
	}
	if err := requireCoreDeterministic(content, mode); err != nil {
		return nil, err
	}
	var fields []cbor.RawMessage
	if err := mode.Unmarshal(content, &fields); err != nil || len(fields) != 4 {
		return nil, errors.New("invalid strict COSE_Sign1")
	}
	var protected, payload, signature []byte
	if err := mode.Unmarshal(fields[0], &protected); err != nil {
		return nil, err
	}
	if err := mode.Unmarshal(fields[2], &payload); err != nil {
		return nil, err
	}
	if err := mode.Unmarshal(fields[3], &signature); err != nil {
		return nil, err
	}
	if err := requireCoreDeterministic(protected, mode); err != nil {
		return nil, err
	}
	var headers map[int64]cbor.RawMessage
	if err := mode.Unmarshal(protected, &headers); err != nil || len(headers) != 2 {
		return nil, errors.New("strict Device EAT requires alg and content-type only")
	}
	var algorithm int64
	var mediaType string
	if err := mode.Unmarshal(headers[1], &algorithm); err != nil || algorithm != -35 {
		return nil, errors.New("strict Device EAT requires ES384")
	}
	if err := mode.Unmarshal(headers[3], &mediaType); err != nil || mediaType != eatContentType {
		return nil, errors.New("strict Device EAT content-type mismatch")
	}
	chain, err := parseUnprotectedHeaders(fields[1], mode)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("strict Device EAT leaf lacks digitalSignature usage")
	}
	if now.IsZero() {
		now = time.Now()
	}
	for index, certificate := range chain {
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) || len(certificate.UnhandledCriticalExtensions) > 0 {
			return nil, errors.New("strict Device EAT certificate validity or critical extension failure")
		}
		if index+1 < len(chain) {
			if err := certificate.CheckSignatureFrom(chain[index+1]); err != nil {
				return nil, err
			}
		}
	}
	if err := verifyES384(leaf, protected, payload, signature); err != nil {
		return nil, err
	}
	authorized := false
	for _, key := range expectation.IdentityKeys {
		if publicKeysEqual(key, leaf.PublicKey) {
			authorized = true
		}
	}
	if !authorized {
		return nil, errors.New("strict Device EAT leaf key is not authorized")
	}
	claims, err := parseDeviceClaims(payload, nonce, mode, strictDeviceProfile)
	if err != nil {
		return nil, err
	}
	var raw map[int64]cbor.RawMessage
	if err := mode.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}
	if encoded, exists := raw[claimUEID]; exists {
		var identity []byte
		if err := mode.Unmarshal(encoded, &identity); err != nil || !bytes.Equal(identity, expectation.Identity) {
			return nil, errors.New("strict Device EAT UEID is not authorized")
		}
	}
	claims.SigningKey = leaf.PublicKey
	return claims, nil
}
