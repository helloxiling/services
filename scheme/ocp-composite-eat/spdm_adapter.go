// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/veraison/corim/comid"
	commonspdm "github.com/veraison/services/scheme/ocp-composite-eat/internal/spdm"
)

type authenticatedComponent struct {
	Identity     string
	Measurements []comid.ValueTriple
	Dimensions   ComponentDimensions
}

func verifySPDMComponent(
	evidence commonspdm.Evidence,
	nonce []byte,
	expectation MemberExpectation,
	currentTime time.Time,
	allowSPDM10ReversedECDSA bool,
) (*authenticatedComponent, error) {
	result, verifyErr := commonspdm.NewExperimentalVerifier().Verify(context.Background(), evidence, commonspdm.Policy{
		ExpectedNonce: nonce, AuthorizedLeafKeys: expectation.IdentityKeys,
		CurrentTime: currentTime, AllowSPDM10: slices.Contains(expectation.Policy.Evidence.SPDMVersions, 0x10), AllowSPDM12: slices.Contains(expectation.Policy.Evidence.SPDMVersions, 0x12),
		AllowSPDM10ReversedECDSA: allowSPDM10ReversedECDSA,
		MeasurementTypePolicy:    commonspdm.MeasurementTypePolicy(expectation.Policy.Evidence.SPDMMeasurementTypePolicy),
		AllowedBaseHashes:        convertedStrings[commonspdm.BaseHashAlgorithm](expectation.Policy.Evidence.BaseHashes),
		AllowedBaseAsym:          convertedStrings[commonspdm.BaseAsymAlgorithm](expectation.Policy.Evidence.BaseAsym),
	})
	if verifyErr != nil && result == nil {
		return nil, verifyErr
	}
	identity := DimensionResult{Status: OutcomeIndeterminate, Reason: "no independent leaf-key authorization"}
	switch result.IdentityAuthorization {
	case commonspdm.OutcomePass:
		identity = passDimension("SPDM leaf key is authorized")
	case commonspdm.OutcomeFail:
		identity = DimensionResult{Status: OutcomeFail, Reason: "SPDM leaf key is not authorized"}
	}
	dimensions := ComponentDimensions{
		EvidenceProtection: passDimension("SPDM transcript signature and chain mechanics passed"),
		Freshness:          passDimension("SPDM requester nonce matches the challenge"),
		Identity:           identity,
		Composition:        passDimension("component label is present in authenticated topology"),
		Measurements:       DimensionResult{Status: OutcomeIndeterminate, Reason: "measurements not yet appraised"},
		Policy:             passDimension("SPDM version and algorithms are allowed"),
	}
	if result.MeasurementTypeCompatibilityUsed {
		dimensions.Policy = passDimension("SPDM version and algorithms are allowed; signed member policy permits recognized measurement types across versions")
	}
	identityDigest := sha256.Sum256(result.Leaf.RawSubjectPublicKeyInfo)
	component := &authenticatedComponent{Identity: hex.EncodeToString(identityDigest[:]), Dimensions: dimensions}
	if verifyErr != nil {
		var typedError *commonspdm.VerificationError
		if !errors.As(verifyErr, &typedError) {
			return nil, verifyErr
		}
		switch typedError.Kind {
		case commonspdm.ErrorFreshness:
			component.Dimensions.Freshness = DimensionResult{Status: OutcomeFail, Reason: typedError.Error()}
		case commonspdm.ErrorUnsupported, commonspdm.ErrorPolicy:
			unsupported := DimensionResult{Status: OutcomeUnsupported, Reason: typedError.Error()}
			component.Dimensions.Measurements = unsupported
			component.Dimensions.Policy = unsupported
			return component, nil
		default:
			return nil, verifyErr
		}
	}
	measurements, err := spdmMeasurementsToCoMID(expectation.Environment, result)
	if err != nil {
		return nil, err
	}
	component.Measurements = measurements
	return component, nil
}

func convertedStrings[T ~string](values []string) []T {
	result := make([]T, len(values))
	for index, value := range values {
		result[index] = T(value)
	}
	return result
}

func spdmMeasurementsToCoMID(environment comid.Environment, result *commonspdm.Result) ([]comid.ValueTriple, error) {
	measurements := comid.NewMeasurements()
	for _, block := range result.Measurements {
		if block.MeasurementSpecification != 1 {
			return nil, &commonspdm.VerificationError{Kind: commonspdm.ErrorUnsupported, Err: fmt.Errorf("unsupported SPDM measurement specification/type")}
		}
		measurementType, ok := commonspdm.MeasurementTypeName(block.ValueType)
		if !ok {
			return nil, &commonspdm.VerificationError{Kind: commonspdm.ErrorUnsupported, Err: fmt.Errorf("unsupported SPDM measurement type %d", block.ValueType)}
		}
		measurement, err := comid.NewMeasurement(uint(block.Index), comid.UintType)
		if err != nil {
			return nil, err
		}
		measurement.SetName(measurementType)
		if block.RawBitStream {
			measurement.SetRawValueBytes(block.Value, nil)
		} else {
			algorithm := comid.Sha256
			if result.MeasurementHash == commonspdm.MeasurementHashSHA384 {
				algorithm = comid.Sha384
			} else if result.MeasurementHash != commonspdm.MeasurementHashSHA256 {
				return nil, fmt.Errorf("unsupported SPDM measurement hash %q", result.MeasurementHash)
			}
			measurement.Val.Digests = &comid.Digests{*comid.NewDigestIntAlg(algorithm, block.Value)}
		}
		measurements.Add(measurement)
	}
	return []comid.ValueTriple{{Environment: environment, Measurements: *measurements}}, nil
}
