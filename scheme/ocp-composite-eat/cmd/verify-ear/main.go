// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/ear"
	scheme "github.com/veraison/services/scheme/ocp-composite-eat"
)

type sessionResponse struct {
	Result string `json:"result"`
}

func main() {
	sessionPath := flag.String("session", "", "challenge-response session JSON")
	keyPath := flag.String("key", "", "EAR verification JWK")
	nonceHex := flag.String("expected-nonce", "", "expected session nonce in hexadecimal")
	flag.Parse()
	if *sessionPath == "" || *keyPath == "" || *nonceHex == "" {
		fatalf("--session, --key and --expected-nonce are required")
	}
	sessionData, err := os.ReadFile(*sessionPath)
	if err != nil {
		fatalf("read session: %v", err)
	}
	var session sessionResponse
	if err := json.Unmarshal(sessionData, &session); err != nil || session.Result == "" {
		fatalf("session does not contain a signed result")
	}
	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		fatalf("read key: %v", err)
	}
	key, err := jwk.ParseKey(keyData)
	if err != nil {
		fatalf("parse key: %v", err)
	}
	var result ear.AttestationResult
	if err := result.Verify([]byte(session.Result), jwa.ES256(), key); err != nil {
		fatalf("verify EAR: %v", err)
	}
	expected, err := hex.DecodeString(*nonceHex)
	if err != nil {
		fatalf("invalid expected nonce")
	}
	if err := scheme.CheckEARNonce(&result, expected); err != nil {
		fatalf("%v", err)
	}
	encoded, err := result.MarshalJSONIndent("", "  ")
	if err != nil {
		fatalf("encode EAR: %v", err)
	}
	fmt.Println(string(encoded))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
