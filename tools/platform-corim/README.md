# Platform CoRIM Authoring Tool

Use upstream **`cocli`** to create and sign CoRIM artifacts. This repository's
`platform-corim` validates vendor-neutral demo manifests and prepares
CoMID inputs for the experimental Platform CoRIM model. Existing direct-build
and snapshot commands remain for test/legacy workflows; they are not a
replacement for the upstream tooling or a conformance claim.

Producer-specific input formats, converters, internal pipelines and inventory
extraction stay in the producer's own tooling, outside this shared repository.
The verifier consumes supported CoRIM/CoMID contracts; it does not interpret
private source documents embedded in an endorsement.

The [adopter workflow](../../scheme/ocp-composite-eat/docs/adopter-runbook.md) defines issuer roles,
reusable boundaries, lab-baseline approval, and offline/hardware demo gates.

For shared SKU-group endorsements with separate per-server enrollment, use the
[class resolver and multi-server demo](../../scheme/ocp-composite-eat/docs/platform-corim-contract.md). This is the
public path for new class-level adoption; snapshot commands remain for legacy
testing and migration.
The [adopter runbook](../../scheme/ocp-composite-eat/docs/adopter-runbook.md) provides one copyable
path from templates through `cocli`, package assembly, offline appraisal, and the
Veraison challenge-response service.

Commands:

```text
validate-source
build-platform
build-vendor
build-platform-class
build-component-class
export-platform-class
export-component-class
create-class-package
emit-collection-plan
compile-demo-snapshot
inspect
```

Platform manifests own topology labels and operational collection locators.
Vendor manifests contain no `env.*` labels or platform locators and can be
reused across boards. Private keys are rejected in source manifests and are
accepted only as external inputs to `compile-demo-snapshot`.

`compile-demo-snapshot` also requires a signed platform CoRIM, each signed
vendor CoRIM, and independently configured source roots. It rejects signature,
validity, issuer-root, or reviewed-manifest payload mismatches before merging.

Referenced vendor files are confined to the platform manifest's directory by
default. Use `--package-root` when multiple platform directories deliberately
share a vendor manifest within one reviewed source package.

## Upstream Workflow

The tested upstream toolchain is:

- `github.com/veraison/cocli` at `v1.0.0-alpha0.0.20260803103637-7ee926967090`;
- `github.com/veraison/corim` at `v1.1.3-0.20260611115812-7ca640710b0b`;
- `github.com/veraison/go-cose` at `v1.3.0`.

Install with Go and ensure its binary directory is on PATH:

```bash
go install github.com/veraison/cocli@v1.0.0-alpha0.0.20260803103637-7ee926967090
go version -m "$(command -v cocli)"
```

The module revision is authoritative for reproducibility; the installed
`cocli --version` banner reports only `0.0.1`.

For standard CoMID JSON supplied by a producer, upstream supports
`cocli comid create --template <json> --output-dir <existing-directory>`,
followed by `cocli corim create`. The producer must implement a faithful
translation to the chosen CoMID semantics in its own tooling. Unsupported
constraints must not be silently dropped to fit the input schema.

For this reference implementation's experimental class policy, use the helper
to export the exact CoMID bytes and upstream envelope template:

```bash
work=$(mktemp -d)
platform-corim export-component-class \
	--manifest /path/to/component-class.json --output "$work/component"
platform-corim export-platform-class \
	--manifest /path/to/platform-class.json --output "$work/platform"

cocli corim create --template "$work/component/corim-template.json" \
	--comid-dir "$work/component" --output "$work/component.unsigned.cbor"
cocli corim create --template "$work/platform/corim-template.json" \
	--comid-dir "$work/platform" --output "$work/platform.unsigned.cbor"

cocli corim sign --file "$work/component.unsigned.cbor" \
	--key /secure/component-issuer.jwk --cert /secure/component-issuer.der \
	--meta /secure/component-meta.json --output "$work/component.cose"
cocli corim sign --file "$work/platform.unsigned.cbor" \
	--key /secure/platform-issuer.jwk --cert /secure/platform-issuer.der \
	--meta /secure/platform-meta.json --output "$work/platform.cose"
```

Export requires a **new** output directory and refuses to overwrite an existing
one. It writes `corim-template.json` and ordered `comid-*.cbor` files. Do not
round-trip experimental CoMID extensions through generic JSON tools that do
not register those extensions. Passing the encoded CoMID files to `cocli`
preserves their exact bytes. Output binaries belong outside the CoMID directory.

Signing inputs are external ES384/P-384 JWKs with matching DER certificates.
Add `--intermediates` for issuer chains as needed. Metadata uses upstream
`signer` and `validity` fields; complete templates and commands are in the
[adopter runbook](../../scheme/ocp-composite-eat/docs/adopter-runbook.md).
Use demo keys for isolated demos; never distribute issuer private keys in
example packages or install them in the verifier.

Configure the resulting signed sources, issuer roots/scopes and enrollment
through the [class package](../../scheme/ocp-composite-eat/docs/platform-corim-contract.md#service-configuration). The
resolver authenticates certificate paths and signatures and rejects source
drift or tampering. Source/enrollment hashes must be updated after re-signing.

### Validation and Limits

The pinned `cocli create`/`sign` flow is tested end-to-end against the class
resolver. Run its opt-in integration test from the repository root:

```bash
COCLI="$(command -v cocli)" go test ./scheme/ocp-composite-eat \
	-run '^TestUpstreamCocliClassWorkflow$' -count=1 -v
```

It compares exact unsigned bytes, signs both sources with upstream `cocli`,
verifies them through the independently configured resolver, and checks two
positive server bundles plus substitution/missing-member negatives. Temporary
test keys are written only to private test directories and removed afterwards.

At this pinned revision, `cocli corim verify` fails loading a public EC JWK
with an `AssignIfCompatible` error. That command is not a passing gate here;
use the resolver's signature, certificate-path and issuer-scope validation.
Do not supply a signing private key to work around a verification-key error.

Using upstream tooling does not standardize our experimental class policy.
`PlatformClassManifest` and `ComponentReferenceManifest` are local authoring
schemas; the class resolver still expects the declared class contract and
matching reviewed manifests, not arbitrary vendor CoRIMs. General independent
CoRIM/profile ingestion requires a separately supported contract. This change
does not claim such support or promote an existing private conversion result
to standard interoperability.

## Experimental Policy Contract

**Platform CoRIM conceptual model version: 0.5.0.** Platform CoRIM is our
unstandardized proposal for a reusable SKU-group composition endorsement, not
an approved IETF/OCP artifact type. The compiler supports both instance-bound
snapshot examples and shared class-level endorsements. `ClassProvider` resolves
the latter with independent per-server enrollment; see the separate class
contract and its explicit operational limits.

The snapshot encodings use version `0.5.0`, with distinct
identifiers to avoid conflating their processing rules:

| Registry entry | Identifier |
|---|---|
| `platformCorim` (numeric labels) | `tag:example.com,2026:platform-composite-eat-model-index#0.5.0` |
| `platformCorimExplicit` (explicit bindings) | `tag:example.com,2026:platform-composite-eat-explicit#0.5.0` |

Class mode adds the distinct `platformClass` and `componentClass` encodings at
the same conceptual version, documented in the [Platform CoRIM contract](../../scheme/ocp-composite-eat/docs/platform-corim-contract.md#signed-encoding).

Earlier Platform CoRIM `#1.*` identifiers were provisional implementation
labels, not standard versions. They are no longer accepted by this build.
Regenerate and re-sign artifacts; never edit signed bytes or alias the old IDs.
Historical/private captures are preserved unchanged and need explicit reissue
before use with this build. Platform Composite EAT Evidence versioning is unchanged.

Child signing keys use attestation-verification triples. CoMID extension
labels -1 (binding), -2 (member policies), and -3 (vendor policy) carry the
`demo-model-index-v1` binding, required membership, reference-set ID, and Evidence
policy. These are local experimental fields, not OCP-assigned semantics.

Vendor `evidencePolicy` supports `mediaType`, `deviceMode` (`strict` or
`caliptra`), `spdmVersions` (16/18), `baseHashes`, and `baseAsym`. Omitted
policy defaults to strict Device EAT or SPDM 1.2/SHA-384/P-384, and those
defaults are materialized in signed CoRIMs. Runtime feature gates can only
disable support; they cannot broaden signed member policy.

Snapshot compilation requires `--source-authorizations`: an independently
configured JSON map from `platform` and each vendor manifest ID to the exact
authorized signing-certificate SHA-256. Root-path validation alone does not
authorize a signer for these roles. Identical vendor IDs may be reused only
when every compiled payload matches the authenticated source. Snapshot validity
is the intersection of source validity and signer-certificate validity.

`emit-collection-plan` emits the spdmd `environments` / `env` / `match` schema,
with `i2cAddr`, and rejects missing operational locators. Source filesystem
reads are confined with Go's `os.Root`, including symlink resolution.

## Explicit Environment Contract

The opt-in experimental Platform CoRIM profile
`tag:example.com,2026:platform-composite-eat-explicit#0.5.0` supports
arbitrary valid `env.*` labels and separate Lead measurement environments.
The default registry includes it as `platformCorimExplicit`; `platformCorim`
selects the separate numeric model/index encoding, also version `0.5.0`.
Neither identifier is an OCP assignment.

For the explicit encoding, each signed member policy also carries its exact CoMID environment
at policy key 3. Domain membership and label bindings must agree one-to-one:
missing, duplicate, ambiguous, or extra bindings fail. Labels remain distinct
from device identity and collection locators. An instance UEID is optional for
members enrolled by SPDM attestation key; the Lead still requires its enrolled
instance UEID. No device UEID is invented from a certificate fingerprint.

The single signed policy contract uses:

| CoMID extension | Value |
|---|---|
| -1 | `explicit-environment-v1` |
| -2 | Member policies, including exact label/environment bindings |
| -4 | Exact Platform Composite EAT profile URI |
| -5 | Lead measurement environments whose reference triples must be present |

These are local experimental extensions, not standardized dependency or
inventory-enrollment semantics. The snapshot loader rejects explicit fields
under the numeric model/index encoding.

To separate Lead identity from its measured environments, omit the legacy
`platform.references` values (or use an empty array) and supply
`platform.measurementEnvironments`. Each entry contains an upstream
`comid.Environment` JSON object and a `references` array. For example:

```json
{
	"environment": {
		"class": {
			"id": {"type": "bytes", "value": "Ym9vdC1zdGF0ZQ"},
			"model": "boot"
		}
	},
	"references": [
		{
			"keyType": "string",
			"key": "boot-register",
			"representation": "digest",
			"algorithm": "sha-512",
			"value": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"flags": {"is-immutable": true, "is-debug": false}
		}
	]
}
```

The zero digest above is synthetic, not a hardware reference. Class-ID bytes
use the library's base64url encoding; reference measurement bytes use hex.
Environment matching remains exact. This separates the environments; it does
not introduce wildcard selection or weaken identity authorization.

References support SHA-256, SHA-384, SHA-512, and raw bytes. Optional `flags`
use the pinned CoMID boolean flag names. Every specified flag must be present
and equal, including explicit `false`; extra observed flags do not satisfy or
override a required flag. Digest/raw requirements remain conjunctive with flags.
Unknown flag names and unsupported constraints such as SVN fail closed.
Known string/integer hash algorithm identifiers are normalized only in
comparison copies; signed Evidence bytes are never rewritten.

For a different exact Platform Composite EAT profile identifier, use an external
registry with its approved `compositeEat.id` and pass `--registry` to the
compiler commands. Independently set the verifier's `composite-eat-profile`
to the same URI. This opts into the existing strict parser contract; it does
not add arbitrary formats, assigned OIDs, or parser fallback.