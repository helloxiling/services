// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

type Outcome string

const (
	OutcomePass          Outcome = "pass"
	OutcomeFail          Outcome = "fail"
	OutcomeIndeterminate Outcome = "indeterminate"
	OutcomeUnsupported   Outcome = "unsupported"
)

type DimensionResult struct {
	Status Outcome `json:"status"`
	Reason string  `json:"reason,omitempty"`
}

type ComponentDimensions struct {
	EvidenceProtection DimensionResult `json:"evidence-protection"`
	Freshness          DimensionResult `json:"freshness"`
	Identity           DimensionResult `json:"identity"`
	Composition        DimensionResult `json:"composition"`
	Measurements       DimensionResult `json:"measurements"`
	Policy             DimensionResult `json:"policy-acceptance"`
}

type ComponentResult struct {
	Status     Outcome             `json:"status"`
	Reason     string              `json:"reason"`
	Dimensions ComponentDimensions `json:"dimensions"`
}

func passDimension(reason string) DimensionResult {
	return DimensionResult{Status: OutcomePass, Reason: reason}
}

func unresolvedDimensions(status Outcome, reason string) ComponentDimensions {
	result := DimensionResult{Status: status, Reason: reason}
	return ComponentDimensions{
		EvidenceProtection: result, Freshness: result, Identity: result,
		Composition: result, Measurements: result, Policy: result,
	}
}

func dimensionsStatus(dimensions ComponentDimensions) Outcome {
	statuses := []Outcome{
		dimensions.EvidenceProtection.Status, dimensions.Freshness.Status,
		dimensions.Identity.Status, dimensions.Composition.Status,
		dimensions.Measurements.Status, dimensions.Policy.Status,
	}
	result := OutcomePass
	for _, status := range statuses {
		switch status {
		case OutcomeFail:
			return OutcomeFail
		case OutcomeUnsupported:
			result = OutcomeUnsupported
		case OutcomeIndeterminate:
			if result == OutcomePass {
				result = OutcomeIndeterminate
			}
		case OutcomePass:
		default:
			if result == OutcomePass {
				result = OutcomeIndeterminate
			}
		}
	}
	return result
}
