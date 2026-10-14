# Class Endorsements and Instance Enrollment

Platform CoRIM conceptual model `0.5.0` is an experimental proposal, not an
IETF or OCP standard. Class mode uses one signed SKU-group Platform class CoRIM,
one or more shared component reference CoRIMs, and separate trusted enrollment
for each physical server. Both offline appraisal and the Veraison service use
the same `ClassProvider` through `EndorsementProvider`.

Use the [adopter runbook](adopter-runbook.md) for executable authoring, signing,
package, deployment, and verification commands. This document defines the
contract those commands implement.

## Inputs

| Input | Scope | Contents |
|---|---|---|
| `PlatformClassManifest` | SKU group | ID/revision, Evidence profile, platform and Lead classes, common Lead references, variants |
| `ComponentReferenceManifest` | Component class/release | Source ID, class, reference-set ID, measurement references, native Evidence policy |
| `InstanceEnrollment` | Physical server | ID/revision/validity, Platform revision and variant, SKU/revision, Lead UEID/key, role-to-component keys |
| `ClassEndorsementPackage` | Active verifier package | Relative paths and hashes, enrollment hash, exact signer-certificate scopes |

Complete synthetic schemas are under
[`example/class/manifests/composite-eat-class`](../example/class/manifests/composite-eat-class/README.md).
Class manifests contain no per-device keys or UEIDs. Source signing certificates
identify endorsers, not enrolled devices. Transport locators are not identity or
composition evidence.

## Variants and Selection

Each named Platform variant defines allowed SKU and hardware-revision values and
a complete member-role list. Every role binds a stable Evidence label to an
exact component source ID, component class, reference-set ID, and
required/optional status. Use distinct variants when SKU and revision values
must not be freely combined.

Trusted enrollment selects the Platform revision and variant. The resolver
checks its SKU, hardware revision, Lead class, component classes, and role set.
Every required role must be enrolled. Evidence labels never choose enrollment,
variant, expected inventory, or reference values.

Hardware replacement normally changes enrollment. A firmware release normally
changes a component reference source or Platform class revision. Different
device attestation keys do not require duplicate component class sources.

## Signed Encoding

| Source | Experimental identifier |
|---|---|
| Platform class | `tag:example.com,2026:platform-composite-eat-class#0.5.0` |
| Component class | `tag:example.com,2026:component-reference-class#0.5.0` |

A Platform class source contains one CoMID per variant. Its signed
`sku-group-v1` policy binds class ID/revision, Lead class, variant selection,
Evidence profile, Lead measurement environments, and ordered member roles.
Member position is logical composition metadata, not device identity or proof of
physical location.

A component source contains class-scoped reference triples and a signed
`component-class-v1` policy binding its source ID, component class,
reference-set ID, and Evidence policy. These extensions are local experimental
semantics. They are distinct from the numeric and explicit resolved-snapshot
encodings at the same conceptual version.

## Authentication and Resolution

The provider performs these checks before Evidence can be appraised:

1. Load the operator-selected package and source-root configuration.
2. Confine package-relative reads with `os.Root`; reject absolute paths,
   symlink escapes, oversized files, unknown JSON fields, and trailing JSON.
3. Verify SHA-256 pins for every signed source and the enrollment file.
4. Verify each source CoRIM signature, certificate path, validity, and exact
   signer-certificate scope (`platform` or component source ID).
5. Compile the reviewed JSON manifest and require byte-equivalent authenticated
   source semantics. Resolve dependencies by exact ID, class, and reference set.
6. Validate all enrollment records and reject duplicate enrollment IDs, Lead
   UEIDs, or keys assigned to multiple environments.
7. Resolve the authenticated Lead identity to its enrolled variant and build a
   fresh isolated appraisal context.

Both Lead UEID and key must match enrollment. Component keys are exact approved
leaf-key enrollments; the implementation does not infer class authorization from
certificate subjects. Resolution rechecks source, certificate, and enrollment
validity for every request.

EAR annotations identify the source hashes, enrollment ID/revision, and selected
variant. In class mode, `snapshot-digest` is a digest over selected source
digests and enrollment, not a per-server signed snapshot file.

## Package Trust Boundary

`platform-corim create-class-package` derives source hashes, enrollment hash,
and lowercase SHA-256 fingerprints of the exact DER signer certificates. It
also ensures every runtime artifact path is relative to the package root.

The package and enrollment are trusted operator configuration. A hash stored in
the same mutable file is not an independent trust anchor. Protect package
approval, monotonic activation, filesystem permissions, rollback prevention,
and deployment through an adopter-owned control plane.

An unchanged released producer that emits the legacy direct-map carriage needs
an operator-owned compatibility file passed with `--compatibility`. Each entry
binds `direct-map` to an exact component source ID and the SHA-256 digest of its
signed source CoRIM. Missing entries, unknown sources, unsupported carriage
names, and digest mismatches fail closed. Enrollment cannot select or override
this policy.

Configure exactly one provider mode:

```yaml
scheme:
  OCP_COMPOSITE_EAT:
    class-package: /run/endorsements/class-package.json
    endorsement-roots: /run/trust/approved-source-roots.pem
    evidence-roots: /run/trust/approved-lead-roots.pem
    native-spdm: true
    caliptra-compatibility: false
```

`endorsement-roots` authenticates original Platform/component source issuers;
there is no class-mode snapshot re-signer. The configured Platform Composite EAT profile
must match both the signed Platform class and Lead Evidence exactly.

## Limits

- One active SKU-group class per provider process, with multiple variants and
  enrollments.
- Static file-backed loading; activation requires a restart or rolling
  deployment.
- Exact leaf-key enrollment; no CA-to-class delegation.
- No remote source discovery, arbitrary CoRIM ingestion, revocation service,
  hot reload, or persistent anti-rollback counter.
- Exact CoMID environment equality and only the native Evidence algorithms and
  measurement semantics listed in [README.md](README.md#known-limits).
- A passing recorded-Evidence test proves compatibility, not current hardware
  liveness or independent approval of references and identities.

Production control-plane requirements and release gates are in
[production-readiness.md](production-readiness.md).