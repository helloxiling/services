// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	scheme "github.com/veraison/services/scheme/ocp-composite-eat"
)

func main() {
	bundlePath := flag.String("bundle", "", "Composite EAT bundle")
	platformCoRIMPath := flag.String("platform-corim", "", "signed Platform CoRIM")
	classPackagePath := flag.String("class-package", "", "trusted class source/enrollment package; mutually exclusive with platform-corim")
	endorsementRootsPath := flag.String("endorsement-roots", "", "PEM roots for the Platform CoRIM signer")
	evidenceRootsPath := flag.String("evidence-roots", "", "PEM roots for the Lead Attester")
	nonceHex := flag.String("expected-nonce", "", "32-byte challenge in hexadecimal")
	caliptraCompatibility := flag.Bool("caliptra-compatibility", false, "enable the experimental Caliptra Device EAT adapter")
	nativeSPDM := flag.Bool("native-spdm", false, "enable the experimental captured-SPDM verifier")
	evidenceProfile := flag.String("composite-eat-profile", scheme.CompositeEATProfile, "exact profile URI for the supported strict Composite EAT contract")
	flag.Parse()

	for name, value := range map[string]string{
		"bundle":            *bundlePath,
		"endorsement-roots": *endorsementRootsPath, "evidence-roots": *evidenceRootsPath,
		"expected-nonce": *nonceHex,
	} {
		if value == "" {
			fatalf("--%s is required", name)
		}
	}
	nonce, err := hex.DecodeString(strings.TrimSpace(*nonceHex))
	if err != nil || len(nonce) != 32 {
		fatalf("--expected-nonce must be exactly 32 bytes of hexadecimal")
	}
	endorsementRoots, err := scheme.LoadPEMRoots(*endorsementRootsPath)
	if err != nil {
		fatalf("%v", err)
	}
	evidenceRoots, err := scheme.LoadPEMRoots(*evidenceRootsPath)
	if err != nil {
		fatalf("%v", err)
	}
	provider, err := scheme.LoadEndorsementProvider(*platformCoRIMPath, *classPackagePath, endorsementRoots, *evidenceProfile, time.Now())
	if err != nil {
		fatalf("%v", err)
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		fatalf("read bundle: %v", err)
	}
	engine := scheme.Engine{
		CompositeEATProfile: *evidenceProfile,
		EndorsementProvider: provider, EvidenceRoots: evidenceRoots,
		EnableNativeSPDM:            *nativeSPDM,
		EnableCaliptraCompatibility: *caliptraCompatibility,
		Limits:                      scheme.DefaultLimits(), Now: time.Now,
	}
	report, err := engine.Verify(bundle, nonce)
	if err != nil {
		fatalf("verification failed: %v", err)
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fatalf("encode report: %v", err)
	}
	fmt.Println(string(encoded))
	if report.Status != scheme.OutcomePass {
		os.Exit(2)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
