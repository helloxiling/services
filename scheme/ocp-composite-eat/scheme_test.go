// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ocp_composite_eat

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/corim"
	"github.com/veraison/ear"
	"github.com/veraison/services/plugin"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/compiler"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
	"github.com/veraison/services/vts/appraisal"
)

func TestHandlerUsesInternalEndorsements(t *testing.T) {
	require.False(t, NewHandler().UsesExternalEndorsements())
}

func TestUpstreamCocliClassWorkflow(t *testing.T) {
	cocli := os.Getenv("COCLI")
	if cocli == "" {
		t.Skip("set COCLI to the pinned upstream cocli executable")
	}
	now := time.Now().UTC().Truncate(time.Second)
	demo, err := newClassDemo(now)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	run := func(arguments ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, cocli, arguments...).CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	packageSource := func(unsigned *corim.UnsignedCorim, scope string) []byte {
		t.Helper()
		directory := t.TempDir()
		files, err := compiler.ExportCocliInputs(unsigned)
		require.NoError(t, err)
		var names []string
		for name, data := range files {
			require.NoError(t, os.WriteFile(filepath.Join(directory, name), data, 0o600))
			if strings.HasSuffix(name, ".cbor") {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		unsignedPath := filepath.Join(directory, "unsigned.cbor")
		arguments := make([]string, 0, 6+2*len(names))
		arguments = append(arguments, "corim", "create", "--template", filepath.Join(directory, "corim-template.json"), "--output", unsignedPath)
		for _, name := range names {
			arguments = append(arguments, "--comid", filepath.Join(directory, name))
		}
		run(arguments...)
		actual, err := os.ReadFile(unsignedPath)
		require.NoError(t, err)
		expected, err := unsigned.ToCBOR()
		require.NoError(t, err)
		require.Equal(t, expected, actual, "cocli must preserve the exact class contract")
		issuer, err := demoMakeCertificate(nil, nil, true, "Synthetic Upstream Signing Authority", now)
		require.NoError(t, err)
		roots.AddCert(issuer.Cert)
		encodeInteger := func(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
		publicKey, err := issuer.Key.PublicKey.Bytes()
		require.NoError(t, err)
		privateKey, err := issuer.Key.Bytes()
		require.NoError(t, err)
		publicJWK := map[string]string{
			"kty": "EC", "crv": "P-384", "alg": "ES384",
			"x": encodeInteger(publicKey[1:49]),
			"y": encodeInteger(publicKey[49:]),
		}
		publicJWK["d"] = encodeInteger(privateKey)
		privateData, err := json.Marshal(publicJWK)
		require.NoError(t, err)
		keyPath, certPath := filepath.Join(directory, "issuer.jwk"), filepath.Join(directory, "issuer.der")
		metaPath := filepath.Join(directory, "meta.json")
		require.NoError(t, os.WriteFile(keyPath, privateData, 0o600))
		require.NoError(t, os.WriteFile(certPath, issuer.DER, 0o600))
		meta := corim.NewMeta().SetSigner("Synthetic Upstream Signing Authority", nil).SetValidity(unsigned.RimValidity.NotAfter, unsigned.RimValidity.NotBefore)
		metaData, err := json.Marshal(meta)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(metaPath, metaData, 0o600))
		signedPath := filepath.Join(directory, "signed.cose")
		run("corim", "sign", "--file", unsignedPath, "--key", keyPath, "--cert", certPath, "--meta", metaPath, "--output", signedPath)
		fingerprint := sha256.Sum256(issuer.DER)
		demo.Input.SignerScopes[scope] = hex.EncodeToString(fingerprint[:])
		signed, err := os.ReadFile(signedPath)
		require.NoError(t, err)
		return signed
	}
	platform, err := compiler.BuildPlatformClass(demo.Input.Platform)
	require.NoError(t, err)
	demo.Input.SignedPlatform = packageSource(platform, "platform")
	for id, source := range demo.Input.Components {
		component, err := compiler.BuildComponentClass(source.Manifest)
		require.NoError(t, err)
		source.SignedCoRIM = packageSource(component, id)
		demo.Input.Components[id] = source
	}
	provider, err := NewClassProvider(demo.Input, roots, now)
	require.NoError(t, err)
	engine := Engine{EndorsementProvider: provider, EvidenceRoots: demo.EvidenceRoots, EnableNativeSPDM: true, Limits: DefaultLimits(), Now: func() time.Time { return now }}
	for name, expected := range map[string]Outcome{"server-0-good": OutcomePass, "server-1-good": OutcomePass, "server-0-cross-server": OutcomeFail, "server-1-missing-required": OutcomeFail} {
		report, err := engine.Verify(demo.Bundles[name], demo.Nonce)
		require.NoError(t, err)
		require.Equal(t, expected, report.Status, name)
	}
	demo.Input.SignedPlatform[len(demo.Input.SignedPlatform)-1] ^= 1
	_, err = NewClassProvider(demo.Input, roots, now)
	require.Error(t, err)
}

func TestClassPackageHandlerAndEnrollmentPin(t *testing.T) {
	directory := t.TempDir()
	generated, err := GenerateClassDemoArtifacts(directory)
	require.NoError(t, err)
	params := plugin.NewParameters().SetString("class-package", filepath.Join(directory, "class-package.json")).SetString("endorsement-roots", filepath.Join(directory, "source-roots.pem")).SetString("evidence-roots", filepath.Join(directory, "evidence-roots.pem")).SetBool("native-spdm", true)
	handler := NewHandler()
	require.NoError(t, handler.Init(params))
	nonce, err := hex.DecodeString(generated.Nonce)
	require.NoError(t, err)
	for _, scenario := range []string{"server-0-good", "server-1-good", "server-0-cross-server", "server-1-missing-required"} {
		data, err := os.ReadFile(filepath.Join(directory, scenario+".bundle.cbor"))
		require.NoError(t, err)
		claims, err := handler.ExtractClaims(&appraisal.Evidence{Data: data, Nonce: nonce, MediaType: EvidenceMediaType}, nil)
		require.NoError(t, err)
		result, err := handler.AppraiseClaims(claims, nil)
		require.NoError(t, err)
		if scenario == "server-0-good" || scenario == "server-1-good" {
			require.Equal(t, ear.TrustTierAffirming, *result.Submods[SchemeName].Status)
		} else {
			require.NotEqual(t, ear.TrustTierAffirming, *result.Submods[SchemeName].Status)
		}
		require.Contains(t, *result.Submods[SchemeName].VeraisonAnnotatedEvidence, "enrollment-id")
	}
	params.SetString("platform-corim", "also-configured.cose")
	require.ErrorContains(t, NewHandler().Init(params), "exactly one")
	params.SetString("platform-corim", "")
	params.SetString("composite-eat-profile", "tag:example.com,2026:wrong")
	require.ErrorContains(t, NewHandler().Init(params), "profile")
	params.SetString("composite-eat-profile", CompositeEATProfile)
	path := filepath.Join(directory, "enrollments.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(data, ' '), 0600))
	require.ErrorContains(t, NewHandler().Init(params), "hash mismatch")
}

func TestClassPackagePathConfinement(t *testing.T) {
	directory := t.TempDir()
	_, err := GenerateClassDemoArtifacts(directory)
	require.NoError(t, err)
	roots, err := LoadPEMRoots(filepath.Join(directory, "source-roots.pem"))
	require.NoError(t, err)
	path := filepath.Join(directory, "class-package.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var config ClassPackage
	require.NoError(t, json.Unmarshal(data, &config))
	outside := filepath.Join(t.TempDir(), "outside.json")
	require.NoError(t, os.WriteFile(outside, []byte("{}"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(directory, "escape.json")))
	config.Platform.Manifest = "escape.json"
	encoded, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, encoded, 0600))
	_, err = LoadClassProviderFile(path, roots, time.Now())
	require.Error(t, err)
}

func TestClassPackageCompatibilityPolicy(t *testing.T) {
	directory := t.TempDir()
	_, err := GenerateClassDemoArtifacts(directory)
	require.NoError(t, err)
	path := filepath.Join(directory, "class-package.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var config ClassPackage
	require.NoError(t, json.Unmarshal(data, &config))
	componentData, err := os.ReadFile(filepath.Join(directory, config.Components[0].Manifest))
	require.NoError(t, err)
	var component manifest.ComponentReferenceManifest
	require.NoError(t, json.Unmarshal(componentData, &component))
	config.Compatibility = &platformcorim.CompatibilityPolicy{EvidenceCarriageBySource: map[string]platformcorim.CarriageAuthorization{
		component.ID: {SourceSHA256: config.Components[0].SHA256, Carriage: platformcorim.CarriageDirectMap},
	}}
	data, err = json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
	roots, err := LoadPEMRoots(filepath.Join(directory, "source-roots.pem"))
	require.NoError(t, err)
	provider, err := LoadClassProviderFile(path, roots, time.Now())
	require.NoError(t, err)
	for _, enrollment := range provider.input.Enrollments {
		ueid, err := hex.DecodeString(enrollment.Lead.UEID)
		require.NoError(t, err)
		key, err := enrolledPublicKey(enrollment.Lead.PublicKeyPEM)
		require.NoError(t, err)
		resolved, err := provider.Resolve(context.Background(), EndorsementRequest{Profile: CompositeEATProfile, LeadUEID: ueid, LeadPublicKey: key, VerificationTime: time.Now()})
		require.NoError(t, err)
		for _, member := range resolved.Members {
			require.Equal(t, platformcorim.CarriageDirectMap, member.Carriage)
			require.True(t, member.Compatibility)
		}
	}
}

func TestHandlerReturnsPerComponentEAR(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadSnapshot(fixture.encoded, fixture.endorsementRoots, fixture.now)
	require.NoError(t, err)
	nonce := testNonce()
	bundle := buildCompositeBundle(t, fixture, snapshot, nonce, fixture.deviceKey)
	h := NewHandler()
	h.engine = &Engine{Snapshot: snapshot, EvidenceRoots: fixture.leadRoots, EnableCaliptraCompatibility: true, Limits: DefaultLimits(), Now: func() time.Time { return fixture.now }}

	claims, err := h.ExtractClaims(&appraisal.Evidence{Data: bundle, Nonce: nonce, MediaType: EvidenceMediaType}, nil)
	require.NoError(t, err)
	result, err := h.AppraiseClaims(claims, nil)
	require.NoError(t, err)
	require.Equal(t, ear.TrustTierAffirming, *result.Submods[SchemeName].Status)
	require.Equal(t, ear.TrustTierAffirming, *result.Submods["env.device.0"].Status)
	require.Contains(t, *result.Submods[SchemeName].VeraisonAnnotatedEvidence, "snapshot-digest")
}

func TestEARNonPassingDimensionsNeverAffirm(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeFail, OutcomeUnsupported, OutcomeIndeterminate} {
		for _, dimension := range []string{"protection", "freshness", "identity", "composition", "measurements", "policy"} {
			t.Run(string(outcome)+"/"+dimension, func(t *testing.T) {
				dimensions := unresolvedDimensions(OutcomePass, "verified")
				checks := map[string]*DimensionResult{
					"protection": &dimensions.EvidenceProtection, "freshness": &dimensions.Freshness,
					"identity": &dimensions.Identity, "composition": &dimensions.Composition,
					"measurements": &dimensions.Measurements, "policy": &dimensions.Policy,
				}
				checks[dimension].Status = outcome
				component := ComponentResult{Status: outcome, Dimensions: dimensions}
				if dimension == "composition" {
					component.Status = OutcomePass
				}
				claims, err := reportToMap(&Report{Status: OutcomeFail, Lead: component, Components: map[string]ComponentResult{"env.test.0": component}})
				require.NoError(t, err)
				result, err := NewHandler().AppraiseClaims(claims, nil)
				require.NoError(t, err)
				result.UpdateStatusFromTrustVector()
				for _, appraisal := range result.Submods {
					require.NotEqual(t, ear.TrustTierAffirming, *appraisal.Status)
					if dimension != "identity" {
						require.Equal(t, ear.TrustworthyInstanceClaim, appraisal.TrustVector.InstanceIdentity)
					}
				}
			})
		}
	}
}

func TestExpectedEARNonce(t *testing.T) {
	expected := make([]byte, 32)
	encoded := base64.URLEncoding.EncodeToString(expected)
	result := &ear.AttestationResult{Nonce: &encoded}
	require.NoError(t, CheckEARNonce(result, expected))
	expected[0] = 1
	require.Error(t, CheckEARNonce(result, expected))
	result.Nonce = nil
	require.Error(t, CheckEARNonce(result, expected))
}
