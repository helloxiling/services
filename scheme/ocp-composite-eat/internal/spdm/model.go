// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package spdm

import (
	"crypto"
	"crypto/x509"
	"time"
)

type Version uint8

const (
	Version10 Version = 0x10
	Version11 Version = 0x11
	Version12 Version = 0x12
	Version13 Version = 0x13
)

type BaseHashAlgorithm string

const (
	BaseHashSHA256 BaseHashAlgorithm = "sha-256"
	BaseHashSHA384 BaseHashAlgorithm = "sha-384"
)

type BaseAsymAlgorithm string

const (
	BaseAsymECDSAP256 BaseAsymAlgorithm = "ecdsa-p256"
	BaseAsymECDSAP384 BaseAsymAlgorithm = "ecdsa-p384"
)

type MeasurementHashAlgorithm string

const (
	MeasurementHashRaw    MeasurementHashAlgorithm = "raw"
	MeasurementHashSHA256 MeasurementHashAlgorithm = "sha-256"
	MeasurementHashSHA384 MeasurementHashAlgorithm = "sha-384"
)

type Outcome string

const (
	OutcomePass          Outcome = "pass"
	OutcomeFail          Outcome = "fail"
	OutcomeIndeterminate Outcome = "indeterminate"
)

type SignatureEncoding string

const (
	SignatureEncodingBigEndian      SignatureEncoding = "big-endian"
	SignatureEncodingLegacyReversed SignatureEncoding = "legacy-component-reversed"
)

type MeasurementTypePolicy string

const (
	MeasurementTypePolicyVersionStrict MeasurementTypePolicy = "version-strict"
	MeasurementTypePolicyKnownTypes    MeasurementTypePolicy = "known-types"
)

type Evidence struct {
	SignedMeasurements  []byte
	CertificateChainDER []byte
	VCATranscript       []byte
}

type Policy struct {
	ExpectedNonce            []byte
	AuthorizedLeafKeys       []crypto.PublicKey
	Roots                    *x509.CertPool
	CurrentTime              time.Time
	AllowSPDM10              bool
	AllowSPDM12              bool
	AllowSPDM10ReversedECDSA bool
	MeasurementTypePolicy    MeasurementTypePolicy
	AllowedBaseHashes        []BaseHashAlgorithm
	AllowedBaseAsym          []BaseAsymAlgorithm
}

type Limits struct {
	MaxSignedMeasurementsBytes int
	MaxVCABytes                int
	MaxCertificateChainBytes   int
	MaxCertificates            int
	MaxCertificateBytes        int
	MaxMeasurementRecordBytes  int
	MaxMeasurementBlocks       int
	MaxMeasurementValueBytes   int
	MaxOpaqueBytes             int
}

func DefaultLimits() Limits {
	return Limits{
		MaxSignedMeasurementsBytes: 1024 * 1024,
		MaxVCABytes:                64 * 1024,
		MaxCertificateChainBytes:   256 * 1024,
		MaxCertificates:            8,
		MaxCertificateBytes:        64 * 1024,
		MaxMeasurementRecordBytes:  512 * 1024,
		MaxMeasurementBlocks:       255,
		MaxMeasurementValueBytes:   64 * 1024,
		MaxOpaqueBytes:             1024,
	}
}

type MeasurementBlock struct {
	Index                    uint8
	MeasurementSpecification uint8
	ValueType                uint8
	RawBitStream             bool
	Value                    []byte
}

const (
	MeasurementTypeImmutableROM uint8 = iota
	MeasurementTypeMutableFirmware
	MeasurementTypeHardwareConfiguration
	MeasurementTypeFirmwareConfiguration
	MeasurementTypeManifest
	MeasurementTypeDeviceMode
	MeasurementTypeFirmwareVersion
	MeasurementTypeFirmwareSVN
	MeasurementTypeHashExtend
	MeasurementTypeInformational
	MeasurementTypeStructuredManifest
)

func MeasurementTypeName(valueType uint8) (string, bool) {
	names := [...]string{
		"immutable-rom",
		"mutable-firmware",
		"hardware-config",
		"firmware-config",
		"freeform-manifest",
		"device-mode",
		"mutable-firmware-version",
		"mutable-firmware-svn",
		"hash-extended-measurement",
		"informational",
		"structured-measurement-manifest",
	}
	if int(valueType) >= len(names) {
		return "", false
	}
	return names[valueType], true
}

type Result struct {
	Version                          Version
	BaseHash                         BaseHashAlgorithm
	BaseAsym                         BaseAsymAlgorithm
	MeasurementHash                  MeasurementHashAlgorithm
	RequesterNonce                   []byte
	ResponderNonce                   []byte
	Slot                             uint8
	Leaf                             *x509.Certificate
	CertificateChain                 []*x509.Certificate
	TranscriptDigest                 []byte
	VCAAuthenticated                 bool
	SignatureEncoding                SignatureEncoding
	ChainSignaturesValid             bool
	IdentityAuthorization            Outcome
	RootTrust                        Outcome
	Measurements                     []MeasurementBlock
	MeasurementTypeCompatibilityUsed bool
}
