# Platform Composite EAT Verifier Adopter Runbook

This is the canonical end-to-end runbook for the experimental Platform Composite EAT
scheme in Veraison Services. It covers the reference example and the path for an
adopter to author, package, sign, deploy, and exercise its own class
endorsements.

The implementation is a Veraison scheme, not a standalone verifier service.
Platform CoRIM conceptual model `0.5.0` and its class-policy extensions are
experimental. Completing this runbook demonstrates the implemented contract; it
does not establish standards conformance or production certification.

## Artifact Model

Class mode separates reusable endorsement sources from physical server
enrollment:

| Artifact | Authority | Purpose |
|---|---|---|
| Platform class manifest | Platform integrator | SKU group, variants, Lead policy, expected component roles |
| Platform class CoRIM | Platform endorser | Signed CoRIM containing the compiled Platform class CoMIDs |
| Component class manifest | Component supplier or authorized lab | Component class, Evidence policy, and approved references |
| Component reference CoRIM | Component endorser | Signed CoRIM containing the compiled component reference CoMID |
| Instance enrollment | Manufacturing or operator authority | Per-server Lead UEID/key, component keys, class revision, and variant assignment |
| Class package | Verifier operator | Relative paths, exact source/enrollment hashes, and signer-certificate scopes |

In this repository, "Platform CoRIM" means the signed Platform class source. It
does not contain per-server keys. A component reference CoRIM is a separate
signed source and can have a different issuer. Evidence never selects its class,
variant, enrollment, reference set, or trusted signing authority.

### Standard and Experimental Boundaries

The authoring flow deliberately separates upstream CoRIM operations from this
reference implementation's experimental policy:

| Operation | Tool | Status |
|---|---|---|
| Author ordinary CoMID JSON | Producer tooling or upstream `cocli comid create` | Upstream Veraison implementation |
| Export class-policy CoMID bytes | Repository `platform-corim export-*` | Experimental local class-policy schema |
| Create the CoRIM envelope | Upstream `cocli corim create` | Upstream Veraison implementation |
| Sign the CoRIM | Upstream `cocli corim sign` | Upstream Veraison implementation |
| Bind sources and enrollment into `class-package.json` | Repository `platform-corim create-class-package` | Experimental verifier configuration |

`platform-corim` does not replace `cocli` or define another CoRIM envelope. It
validates the class manifests and exports the exact extension-bearing CoMID
bytes consumed by `cocli`. The commands in Sections 4 through 6 are the
copyable path for this implementation. For a producer that already has ordinary
CoMID JSON, use the upstream flow documented in the
[`platform-corim` tool guide](../../../tools/platform-corim/README.md#upstream-workflow)
instead of translating it through the experimental class manifests.

## Prerequisites

Use Linux with Git, GNU Make, Docker with Buildx, `curl`, `jq`, Python 3,
OpenSSL, `xxd`, and Go 1.26. The current user must be able to run Docker.

Check out the exact reviewed repository revision supplied for the integration:

```bash
git clone <repository-url> composite-eat-verifier
cd composite-eat-verifier
git checkout <reviewed-revision>
export REPO=$PWD
```

Do not use a moving branch as the production package provenance record.

## 1. Run the Reference E2E

Run this before changing any manifests:

```bash
make composite-eat-example
```

The command generates temporary authorities and class sources, invokes the
pinned upstream `cocli`, runs offline appraisal, deploys Veraison, verifies
signed EARs over TLS, and stops the services. The fixture scenarios, expected
outcomes, and generated-output boundary are documented only in
[example documentation](../example/class/README.md).

## 2. Prepare Tools and Protected Directories

Keep package work and signing material outside the source tree:

```bash
export TOOLS=$(mktemp -d)
export WORK=$(mktemp -d)
export PACKAGE=$HOME/composite-eat-packages/revision-42
export SECURE=$HOME/composite-eat-signing
install -d -m 700 "$TOOLS" "$WORK" "$PACKAGE" "$SECURE"

go build -o "$TOOLS/platform-corim" \
  ./tools/platform-corim/cmd/platform-corim
go build -o "$TOOLS/composite-verify" \
  ./scheme/ocp-composite-eat/cmd/composite-verify
GOBIN="$TOOLS" go install \
  github.com/veraison/cocli@v1.0.0-alpha0.0.20260803103637-7ee926967090
"$TOOLS/cocli" --version
```

Record the pinned `cocli` version and repository revision with the package
provenance.

## 3. Author Class Sources and Enrollment

Start from the complete synthetic schemas:

```bash
cp scheme/ocp-composite-eat/example/class/manifests/composite-eat-class/platform-class.json \
  "$PACKAGE/platform-class.json"
cp scheme/ocp-composite-eat/example/class/manifests/composite-eat-class/component-class.json \
  "$PACKAGE/component-class.json"
cp scheme/ocp-composite-eat/example/class/manifests/composite-eat-class/enrollments.example.json \
  "$PACKAGE/enrollments.json"
cp scheme/ocp-composite-eat/example/class/manifests/composite-eat-class/platform-corim-meta.json \
  "$SECURE/platform-corim-meta.json"
cp scheme/ocp-composite-eat/example/class/manifests/composite-eat-class/component-corim-meta.json \
  "$SECURE/component-corim-meta.json"
chmod 600 "$PACKAGE"/* "$SECURE"/*
```

Edit and independently review all copied values:

- Give the Platform class a stable ID and monotonic revision.
- Define each allowed SKU/hardware-revision variant and its complete required
  and optional role set.
- Bind every role to an exact component source ID, component class, and
  reference set ID.
- Derive Lead and component references from approved builds, signed release
  manifests, or an independently reviewed baseline. Never copy measurements
  from the Evidence being appraised and call them approved.
- Create enrollment through an authenticated manufacturing or operator process.
  Enroll the exact Lead UEID/public key and component public keys for each
  physical server. Never use Evidence as an automatic enrollment source.
- Set manifest and CoRIM metadata validity windows deliberately. The effective
  context cannot outlive its source, certificate, or enrollment validity.

Historical packages are expected to fail after that intersection expires.
Reissue and re-sign their current-schema manifests and enrollment for a new
review period; do not edit a signed CoRIM or extend validity only in the package
descriptor.

Use one component manifest per independently versioned class/reference set.
Repeat the component commands below for every source used by a Platform variant.
Record the exact Platform Composite EAT profile selected by the Platform class; both the
offline verifier and deployed service require the same value:

```bash
export COMPOSITE_EAT_PROFILE=$(jq -r '.compositeEatProfile' \
  "$PACKAGE/platform-class.json")
test -n "$COMPOSITE_EAT_PROFILE"
```

Native SPDM component policies are version-strict by default. If authenticated
Evidence uses a measurement type known to the verifier but newer than its
negotiated SPDM version, an endorser may opt that component source into bounded
interoperability handling:

```json
"evidencePolicy": {
  "mediaType": "application/spdm-evidence+cbor",
  "spdmVersions": [18],
  "baseHashes": ["sha-384"],
  "baseAsym": ["ecdsa-p384"],
  "spdmMeasurementTypePolicy": "known-types"
}
```

This signed policy accepts only measurement types already understood by the
verifier. It continues to enforce the DMTF measurement specification,
raw-versus-digest representation, reserved indices, transcript signature,
nonce, identity, algorithms, and approved reference values. Reports identify
when cross-version handling was used. Treat the option as a reviewed migration
measure, not as proof that the producer conforms to the negotiated SPDM
version.

## 4. Create the Unsigned Platform and Component CoRIMs

First compile and validate the authoring manifests. Each export directory must
not already exist:

```bash
"$TOOLS/platform-corim" export-platform-class \
  --manifest "$PACKAGE/platform-class.json" \
  --output "$WORK/platform-inputs"

"$TOOLS/platform-corim" export-component-class \
  --manifest "$PACKAGE/component-class.json" \
  --output "$WORK/component-inputs"
```

Each export contains an upstream `corim-template.json` and exact CBOR CoMID
payloads. Review and hash those files before signing:

```bash
find "$WORK/platform-inputs" "$WORK/component-inputs" -type f \
  -exec sha256sum {} + | sort
```

Create normal unsigned CoRIM envelopes with the pinned upstream tool:

```bash
"$TOOLS/cocli" corim create \
  --template "$WORK/platform-inputs/corim-template.json" \
  --comid-dir "$WORK/platform-inputs" \
  --output "$PACKAGE/platform-class.cbor"

"$TOOLS/cocli" corim create \
  --template "$WORK/component-inputs/corim-template.json" \
  --comid-dir "$WORK/component-inputs" \
  --output "$PACKAGE/component-class.cbor"
```

The first output is the unsigned Platform class CoRIM. The second is the
unsigned component reference CoRIM. `platform-corim` defines and validates the
experimental policy payload; `cocli` creates the standard CoRIM envelope.

## 5. Sign the CoRIMs

Provision signing material through the adopter's PKI or HSM workflow. For each
issuer, `cocli` requires:

- an EC P-384 private key in JWK format, protected outside the package;
- the matching signing certificate in DER format;
- optional intermediate certificates in DER format; and
- reviewed CoRIM metadata naming the signer and validity interval.

The signing certificate must chain to a root that the verifier operator places
in `source-roots.pem`. Platform and component sources may use separate roots.
Attestation keys and CoRIM signing keys are different roles.

Sign the Platform class CoRIM:

```bash
"$TOOLS/cocli" corim sign \
  --file "$PACKAGE/platform-class.cbor" \
  --key "$SECURE/platform-issuer.jwk" \
  --cert "$SECURE/platform-issuer.der" \
  --meta "$SECURE/platform-corim-meta.json" \
  --output "$PACKAGE/platform-class.cose"
```

Sign the component reference CoRIM with its authorized issuer:

```bash
"$TOOLS/cocli" corim sign \
  --file "$PACKAGE/component-class.cbor" \
  --key "$SECURE/component-issuer.jwk" \
  --cert "$SECURE/component-issuer.der" \
  --meta "$SECURE/component-corim-meta.json" \
  --output "$PACKAGE/component-class.cose"
```

Add `--intermediates <chain.der>` when the signing certificate is not directly
issued by a configured root. Never copy private JWKs into `$PACKAGE` or the
verifier deployment.

At the tested pin, `cocli corim verify` cannot load a public EC JWK because of
an upstream type compatibility error. Do not pass a private key as a workaround.
The class resolver verifies the COSE signature, certificate path, validity,
compiled payload, exact source hash, and authorized certificate scope.

## 6. Assemble the Verifier Package

Create trust bundles from independently approved roots:

```bash
cat "$SECURE/platform-root.pem" "$SECURE/component-root.pem" \
  > "$PACKAGE/source-roots.pem"
install -m 600 "$SECURE/approved-lead-roots.pem" \
  "$PACKAGE/evidence-roots.pem"
```

`source-roots.pem` authenticates CoRIM issuers. `evidence-roots.pem`
authenticates Lead Evidence. Neither file is derived from candidate Evidence.

Generate the package descriptor and its exact pins:

```bash
"$TOOLS/platform-corim" create-class-package \
  --platform-manifest "$PACKAGE/platform-class.json" \
  --platform-corim "$PACKAGE/platform-class.cose" \
  --platform-cert "$SECURE/platform-issuer.der" \
  --component "$PACKAGE/component-class.json=$PACKAGE/component-class.cose=$SECURE/component-issuer.der" \
  --enrollments "$PACKAGE/enrollments.json" \
  --output "$PACKAGE/class-package.json"

jq . "$PACKAGE/class-package.json"
sha256sum "$PACKAGE"/*
```

Repeat `--component manifest=corim=certificate` for every component source. All
manifests, signed CoRIMs, enrollment, and files referenced by
`class-package.json` must be inside `$PACKAGE`. Issuer private keys and signing
certificates remain outside it.

For an unchanged released producer that emits the legacy direct-map carriage,
create an operator-reviewed compatibility input using the exact component
source ID and signed source CoRIM digest:

```json
{
  "evidenceCarriageBySource": {
    "tag:example.com,2026:released-component-reference": {
      "sourceSha256": "<sha256-of-signed-component-corim>",
      "carriage": "direct-map"
    }
  }
}
```

Pass it to `create-class-package` with `--compatibility FILE`. Omit this option
for conformant CMW producers. The command rejects unknown source IDs, digest
mismatches, and any carriage other than `direct-map`.

The deployable directory now contains at least:

```text
class-package.json
platform-class.json
platform-class.cose
component-class.json
component-class.cose
enrollments.json
source-roots.pem
evidence-roots.pem
```

## 7. Run the Offline Gate

Appraise an unchanged bundle using the nonce to which it was signed:

```bash
export BUNDLE=/private/evidence/composite-eat.bundle.cbor
export NONCE_HEX=<expected-nonce-in-hex>

"$TOOLS/composite-verify" \
  --class-package "$PACKAGE/class-package.json" \
  --endorsement-roots "$PACKAGE/source-roots.pem" \
  --evidence-roots "$PACKAGE/evidence-roots.pem" \
  --bundle "$BUNDLE" \
  --expected-nonce "$NONCE_HEX" \
  --native-spdm \
  --composite-eat-profile "$COMPOSITE_EAT_PROFILE"
```

Exit `0` means all mandatory appraisals passed. Exit `2` means the Evidence was
successfully evaluated but did not pass. Exit `1` means an operational,
configuration, parsing, or cryptographic verification failure. Gate deployment
on positive and adversarial cases, not only one expected-pass bundle.

## 8. Deploy the Package into Veraison

The Composite scheme remains disabled by default. The Docker reference
deployment accepts a reviewed package directory explicitly:

```bash
make \
  OCP_COMPOSITE_EAT_ENABLED=1 \
  OCP_COMPOSITE_EAT_DEMO_MODE=class \
  OCP_COMPOSITE_EAT_PACKAGE_DIR="$PACKAGE" \
  OCP_COMPOSITE_EAT_PROFILE="$COMPOSITE_EAT_PROFILE" \
  docker-deploy

curl --fail --silent --show-error \
  --cacert deployments/docker/src/certs/rootCA.crt \
  --retry 30 --retry-connrefused --retry-all-errors --retry-delay 1 \
  https://localhost:8443/.well-known/veraison/verification >/dev/null
```

The package is mounted read-only into the deployment builder, copied into the
image context, and loaded when VTS starts. The file-backed provider does not hot
reload. Rebuild and roll the service to activate another revision. The
repository TLS authority is for local reference deployment only.

## 9. Submit Recorded Evidence and Verify the EAR

For a bundle already bound to a known test nonce:

```bash
scheme/ocp-composite-eat/scripts/submit-evidence.sh \
  --bundle "$BUNDLE" \
  --nonce "$NONCE_HEX" \
  --tls-ca deployments/docker/src/certs/rootCA.crt
```

The client creates a challenge-response session, submits exact bundle bytes,
retrieves the advertised EAR verification key over trusted TLS, verifies the
EAR signature and nonce, and prints the EAR claims. Script success proves the
protocol and EAR checks completed; inspect every required EAR status to decide
whether the platform appraisal passed.

## 10. Run a Fresh Hardware Session

For live hardware, create the Veraison session before collection:

```bash
export NONCE_HEX=$(openssl rand -hex 32)
export NONCE_B64URL=$(printf '%s' "$NONCE_HEX" | xxd -r -p | \
  base64 -w0 | tr '+/' '-_' | tr -d '=')
headers=$(mktemp)

curl --fail --silent --show-error \
  --cacert deployments/docker/src/certs/rootCA.crt \
  --request POST --dump-header "$headers" \
  --header 'Accept: application/vnd.veraison.challenge-response-session+json' \
  "https://localhost:8443/challenge-response/v1/newSession?nonce=$NONCE_B64URL" \
  >/dev/null

export SESSION=$(awk 'BEGIN {IGNORECASE=1} /^Location:/ {gsub("\r", "", $2); print $2}' "$headers")
test -n "$SESSION"
```

### Session Provenance

This session sequence is the existing Veraison Challenge/Response API, not a
Platform Composite EAT-specific protocol:

- The published [Veraison Challenge/Response API](https://github.com/veraison/docs/tree/main/api/challenge-response)
  defines `POST /challenge-response/v1/newSession`, a time-bounded nonce and
  expiry, a session resource returned in `Location`, Evidence submission to
  that resource, optional polling, and deletion.
- The current service registers those routes in
  [`verification/api/router.go`](../../../verification/api/router.go) and stores
  nonce, expiry, accepted media types, state, Evidence, and result in
  [`ChallengeResponseSession`](../../../verification/api/challengeresponsesession.go).
- The repository's established
  [end-to-end integration test](../../../integration-tests/tests/test_end_to_end.tavern.yaml)
  creates a session, submits Evidence to the returned `Location`, and deletes
  the session. Deployment clients point at the same endpoint.
- The session resource and lifecycle entered the public Veraison Services
  history in [commit `63ad7932`](https://github.com/veraison/services/commit/63ad7932b0ac88f6d5e86b53c98676b927b5a25b)
  in July 2022, before this Platform Composite EAT scheme.

Veraison describes this API as an instantiation of the IETF RATS reference
interaction models; the concrete HTTP resources are Veraison API practice, not
an IETF-standardized wire protocol. This branch reuses that API unchanged for
Platform Composite EAT. Complete collection and submission before the session's
advertised expiry. A longer collection window requires a separate, generic
verification-service change and is not part of this scheme.

Pass `NONCE_HEX` to the adopter's authenticated collector and preserve the exact
returned bundle bytes as `$BUNDLE`. Collector integration is producer-specific
and intentionally outside this verifier repository. Then submit to the existing
session:

```bash
scheme/ocp-composite-eat/scripts/submit-evidence.sh \
  --session "$SESSION" \
  --bundle "$BUNDLE" \
  --nonce "$NONCE_HEX" \
  --tls-ca deployments/docker/src/certs/rootCA.crt
```

Archive the package digest, implementation revision, session ID, nonce, exact
Evidence hash, signed EAR, and appraisal decision according to the adopter's
privacy and audit policy.

Stop the local reference deployment when finished:

```bash
deployments/docker/veraison stop
```

## Production Boundary

The file-backed provider is a reference integration, not a production trust
control plane. Before production use, implement the activation, anti-rollback,
revocation, HSM, authenticated enrollment, availability, monitoring, audit, and
incident-response controls in [production-readiness.md](production-readiness.md).
The signed class encoding and supported native Evidence formats are bounded by
[README.md](README.md). Detailed class resolution semantics are documented in
[platform-corim-contract.md](platform-corim-contract.md).