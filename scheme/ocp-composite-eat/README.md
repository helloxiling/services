# OCP Platform Composite EAT Scheme

This experimental Veraison scheme verifies the draft OCP Platform Composite EAT profile
using authenticated class endorsements plus trusted instance enrollment, or an
existing immutable resolved snapshot.

Platform CoRIM is our unstandardized conceptual model, version `0.5.0`, for
SKU-group composition endorsement. The class resolver and per-instance snapshot
mode are experimental implementations, not an approved standard. The Composite
EAT Evidence version is separate and unchanged.

Implemented checks include:

- tag-602 Detached EAT Bundle and deterministic CBOR validation;
- strict Platform Composite EAT claims and COSE headers;
- Lead Attester X.509 path, `x5t`, ES384 signature, UEID authorization, and
  nonce validation;
- exact-byte detached Claims-Set SHA-384 binding and key-set equality;
- required Platform CoRIM membership and slot-to-identity authorization;
- Caliptra-compatible OCP Device EAT signatures, nonces, debug state, and
  tagged Concise Evidence;
- environment-scoped reference-value appraisal; and
- per-platform, Lead, and component EAR results.

## Snapshot mode

The handler advertises only `application/eat-bun+cbor`. It deliberately does
not advertise provisioning media types. At startup it requires:

```yaml
scheme:
  OCP_COMPOSITE_EAT:
    platform-corim: /path/to/platform.corim.cose
    endorsement-roots: /path/to/endorsement-roots.pem
    evidence-roots: /path/to/evidence-roots.pem
    native-spdm: true
    caliptra-compatibility: true
```

  The Docker deployment omits this configuration and its demo artifacts by
  default. Set `OCP_COMPOSITE_EAT_ENABLED=1` on the Docker make command to opt in.

The signed Platform CoRIM uses the experimental profile
`tag:example.com,2026:platform-composite-eat-model-index#0.5.0`.
For this implementation, a member's signed class model and index project to
`env.<model>.<index>`. Its instance and attestation-verification key remain separate
native identity constraints.

## Class Mode

Set `class-package` instead of `platform-corim` to resolve shared SKU-group
Platform/component CoRIMs using independently trusted server enrollment. Exactly
one provider mode must be configured. `endorsement-roots` authenticates original
source issuers in this mode; no snapshot signer is involved.

See the [Platform CoRIM contract](docs/platform-corim-contract.md)
for generated inputs, signing, pinning, positive/negative CLI cases and service
settings. The class-level provider never selects a variant from observed labels.
EAR annotations identify the selected sources, enrollment revision and variant.
Use the [adopter runbook](docs/adopter-runbook.md)
for a complete runnable workflow.

## Explicit Endorsement Contract

The optional explicit-binding encoding
`tag:example.com,2026:platform-composite-eat-explicit#0.5.0` adds
signed label/environment bindings and separate Lead measurement environments.
It coexists with the numeric-binding encoding at the same conceptual version.
Old provisional Platform CoRIM `#1.*` identifiers are not accepted or aliased;
regenerate and re-sign snapshots rather than rewriting signed artifacts.
See the [authoring CLI](../../tools/platform-corim/README.md#explicit-environment-contract)
and [adopter workflow](docs/adopter-runbook.md).

The service setting `composite-eat-profile` defaults to the existing demo URI.
An operator may explicitly configure another absolute URI for the same strict
Platform Composite EAT decoding contract. That exact URI must also be in the signed
explicit-binding snapshot and the Lead token. A mismatch fails; this is not a profile
alias or parser fallback. No lab-specific URI is compiled into the engine.

For offline appraisal from the repository root:

```bash
go run ./scheme/ocp-composite-eat/cmd/composite-verify \
  --bundle /private/capture.bundle.cbor \
  --platform-corim /private/resolved.snapshot.cose \
  --endorsement-roots /private/snapshot-roots.pem \
  --evidence-roots /private/approved-lead-roots.pem \
  --composite-eat-profile tag:example.com,2026:strict-composite-v1 \
  --expected-nonce "$EXPECTED_NONCE_HEX" --native-spdm
```

The CLI emits an appraisal report, not a signed session EAR. Build and invoke
the binary directly when testing exact exit codes (`go run` wraps nonzero
program exits). Source signer keys are never required by this verifier command.

The authoring/appraisal path supports SHA-512 and specified boolean flags in
addition to existing raw/SHA-256/SHA-384 references. Every required flag must
be present and match. Unsupported constraints still produce non-pass outcomes.

## Caliptra interoperability mode

The signed member policy selects strict or Caliptra decoding before parsing.
Strict mode accepts the bounded ES384 subset with self-describe/CWT/Sign1 tags,
protected alg and `application/eat+cwt`, unprotected x5chain only, and the
untagged BER OID value from the current Device EAT CDDL. No parser fallback is
performed. This subset is not a claim of complete OCP Device EAT conformance
while the source specification's algorithm/header/profile text is inconsistent.

The current Caliptra MCU producer uses CBOR self-describe, CWT, and COSE_Sign1
tags; protected `{1: -35}`; an unprotected 48-byte `kid`; profile claim 265 as
tag 111 wrapping UTF-8 dotted OID text; and tagged Concise Evidence. When
`caliptra-compatibility` is true, the adapter supports that exact subset and
resolves the signing key from the authenticated Platform CoRIM.

This mode is intentionally named and isolated because the local OCP Device EAT
specification requires `x5chain` and has unresolved text/encoding differences.
The Platform Composite EAT main token remains strict to its own profile.

## Native SPDM mode

Set `native-spdm: true` to enable the experimental captured-SPDM verifier. It
supports SPDM 1.0 and 1.2 with ECDSA P-256/P-384 and SHA-256/SHA-384. Legacy
SPDM 1.0 component-reversed ECDSA remains disabled unless
`spdm-1.0-reversed-ecdsa: true` is also configured.

Measurement types are checked against the negotiated SPDM version by default.
A signed component Evidence policy may set `spdmMeasurementTypePolicy` to
`known-types` to accept only the verifier's recognized type vocabulary across
version boundaries. Authentication, representation, index, identity, and
reference-value checks remain mandatory, and appraisal reports disclose use of
this interoperability mode. It does not establish SPDM conformance for the
producer.

## Known limits

- Appraisal supports raw values, digests, and specified boolean flags
  conjunctively. Other reference constraints (including SVN) return unsupported,
  never a silent pass.
- Failed or unresolved required dimensions always produce non-affirming EARs.

- File-backed shared-class/enrollment and resolved-snapshot modes; ordinary
  Veraison CoRIM provisioning, dynamic inventory storage and revocation are not connected.
- Recursive Platform Composite EAT is rejected. Native SPDM is experimental and limited
  to the versions and algorithms documented above.
- Reference environments currently require exact CoMID equality. Real vendor
  evidence may require a profile-defined selector relation while retaining a
  separate native identity check.
- Certificate revocation is not implemented in this demo.
- The `.1.4` Composite profile identifier is draft-only pending OCP assignment.
- Generated bundles prove recorded-evidence behavior, not present-time hardware
  liveness. The live collection client remains future integration work.

See [example/class/README.md](example/class/README.md) for commands and scenarios. See
[production readiness](docs/production-readiness.md) for the architecture decision,
mandatory production control-plane responsibilities, and release gates.

## Security Regression Coverage

The tests cover non-affirming EARs for failed/unresolved required dimensions,
cross-format key reuse, strict-versus-Caliptra no-fallback behavior, conjunctive
raw/digest constraints, unsupported SVN, missing references, scoped source
issuers, conflicting vendor payloads/keys/policies, source expiry, symlink
confinement, and malformed SPDM negotiation. The mixed HTTP matrix checks
authenticated TLS, signed nonce equality, and non-affirming negative EARs.

The canonical builder still needs Python for the repository copyright check;
run its recursive test target with `CI_PIPELINE=1` to use the existing CI
copyright-year policy. A passing synthetic suite is not a production
certification or a completed hardware demo.