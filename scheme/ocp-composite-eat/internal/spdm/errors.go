// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package spdm

import "fmt"

type ErrorKind string

const (
	ErrorMalformed   ErrorKind = "malformed-evidence"
	ErrorUnsupported ErrorKind = "unsupported"
	ErrorFreshness   ErrorKind = "freshness"
	ErrorSignature   ErrorKind = "signature"
	ErrorCertificate ErrorKind = "certificate"
	ErrorPolicy      ErrorKind = "policy"
)

type VerificationError struct {
	Kind ErrorKind
	Err  error
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("%s: %v", e.Kind, e.Err)
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

func verificationError(kind ErrorKind, format string, args ...any) error {
	return &VerificationError{Kind: kind, Err: fmt.Errorf(format, args...)}
}
