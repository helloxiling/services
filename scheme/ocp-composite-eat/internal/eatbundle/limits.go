// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package eatbundle

const (
	defaultMaxBundleBytes    = 8 * 1024 * 1024
	defaultMaxClaimsSetBytes = 1024 * 1024
	defaultMaxSubmodules     = 64
	defaultMaxNestedLevels   = 16
)

type Limits struct {
	MaxBundleBytes    int
	MaxClaimsSetBytes int
	MaxSubmodules     int
	MaxNestedLevels   int
}

func DefaultLimits() Limits {
	return Limits{
		MaxBundleBytes:    defaultMaxBundleBytes,
		MaxClaimsSetBytes: defaultMaxClaimsSetBytes,
		MaxSubmodules:     defaultMaxSubmodules,
		MaxNestedLevels:   defaultMaxNestedLevels,
	}
}
