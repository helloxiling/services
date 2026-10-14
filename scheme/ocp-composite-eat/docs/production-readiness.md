# Production Readiness

## Decision

The class-endorsement architecture is production-oriented, but this repository
is a reference implementation rather than a complete production trust-control
plane. It provides the data contracts, cryptographic verification, class
resolution, appraisal engine, and Veraison scheme integration. An adopter must
integrate those pieces with its production endorsement, enrollment, activation,
revocation, monitoring, and audit systems.

Platform CoRIM conceptual model version `0.5.0` and its class-policy extensions
are experimental. Upstream `cocli` packages and signs the artifacts, but using
that tool does not make the experimental policy a standardized CoRIM profile.

## Production-Oriented Properties

- Shared Platform and component class sources contain no per-device private
  material or instance identities. Instance enrollment has a separate lifecycle.
- Signed source bytes are authenticated against configured roots, exact signer
  certificate scopes, validity windows, reviewed manifests, and SHA-256 pins.
- Evidence cannot choose its class, variant, expected membership, references,
  or authorized key. Trusted enrollment makes those selections.
- Lead and component identities are independently enrolled. A valid signature
  from another enrolled server does not authorize cross-server substitution.
- The verifier preserves signed Evidence bytes, checks the session nonce, and
  fails closed for unsupported policy or reference constraints.
- Each appraisal receives a fresh resolved context. Construction takes an
  owned immutable copy of the active package, and concurrent requests do not
  share mutable appraisal state.
- Class-package paths are confined to the package directory, files are bounded,
  JSON is strict, and source/enrollment changes invalidate configured hashes.

## Required Production Control Plane

The following controls are intentionally not implemented by the file-backed
reference provider and are mandatory responsibilities for a production adopter:

| Control | Production requirement |
|---|---|
| Reference provenance | Derive references from approved builds, release manifests, or independently reviewed lab baselines; never from the Evidence currently being appraised. |
| Signing authority | Protect issuer keys with the adopter's PKI/HSM process; define issuer roles, certificate profiles, rotation, and compromise response. |
| Enrollment authority | Authenticate manufacturing/operator enrollment, ownership transfer, replacement, and decommissioning. Evidence is not an enrollment source. |
| Activation and rollback | Store active package identity and monotonic revision in durable trusted state; require an audited two-person or equivalent approval before atomic activation; reject stale revisions. |
| Revocation | Check source-signing and attestation-key revocation using the adopter's authoritative service or deny list before activation/appraisal. The reference provider has no CRL/OCSP or remote key-status integration. |
| Availability | Replicate approved packages and deploy them atomically across verifier instances. The file provider loads at startup and does not implement hot reload. |
| Monitoring | Alert before source, certificate, and enrollment expiry; monitor rejection rates, active package digest, enrollment revision, and service health. Do not add an automatic expiration grace pass. |
| Audit | Record package approval, source hashes, signer scopes, enrollment revision, verifier configuration, session ID/nonce, EAR, and outcome without logging private keys or sensitive Evidence indiscriminately. |
| Transport | Use authenticated TLS, authenticate the advertised EAR key, and bind collection and submission to the same fresh Veraison session nonce. |

The safest integration boundary is an adopter-owned control plane that writes a
complete versioned package into a new read-only directory, verifies it offline,
records its digest/revision in durable state, and atomically switches a service
deployment to that directory. Never update files in an active package in place.

## Reference-Implementation Limits

- One active SKU-group class per provider process.
- Static file-backed source and enrollment loading; restart or rolling deployment
  is required to activate a new package.
- Exact enrolled leaf keys; no CA-to-class delegation or certificate-extension
  authorization semantics.
- No dynamic endorsement discovery, remote inventory database, CRL/OCSP,
  persistent anti-rollback counter, or administrative activation API.
- Exact CoMID environment equality and the bounded native Evidence algorithms
  documented in the scheme README.
- Experimental Platform/component class semantics and native SPDM adapter.

These limits are acceptable for a reference implementation only when they are
made explicit. A deployment must not be described as production-ready until the
control-plane requirements above are implemented and exercised in its own threat
model, availability design, incident response, and conformance program.

## Release Gates

1. Review the platform class, every component reference set, and every enrollment
   independently of the candidate Evidence.
2. Build and sign with pinned tooling, then assemble the package with
  `platform-corim create-class-package`.
3. Run offline positive and adversarial appraisal, including wrong keys, missing
   members, modified measurements, wrong nonce, expired sources, unauthorized
   signers, source drift, and attempted revision rollback.
4. Activate a new immutable package revision through the production control
   plane and verify the active digest on every verifier instance.
5. Run a fresh hardware session through trusted TLS and verify the signed EAR,
   nonce, and all required per-component outcomes.
6. Exercise key compromise, revocation, package rollback, expiry alerting,
   failed rollout, and recovery procedures before accepting production traffic.

The runnable synthetic workflow is documented in the
[adopter runbook](adopter-runbook.md).