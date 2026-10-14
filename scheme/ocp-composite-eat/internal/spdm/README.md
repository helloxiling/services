# Experimental Captured-SPDM Verifier

This package authenticates bounded, captured SPDM SignedMeasurements for the
Platform Composite EAT demonstration. It supports SPDM 1.0 and 1.2 with ECDSA P-256 or
P-384 and SHA-256 or SHA-384. SPDM 1.0 component-reversed ECDSA encoding is an
explicit compatibility option.

The verifier separates transcript/signature validity, requester freshness,
certificate-chain mechanics, independently configured root trust, and leaf-key
authorization. A self-consistent carried certificate chain never becomes a
trust anchor.

DMTF measurement blocks are parsed without assigning semantics before the
signed transcript is authenticated. After signature and freshness checks, the
verifier enforces the measurement-type vocabulary and representation rules for
the negotiated SPDM version, including reserved-index constraints. An
authenticated block with unsupported semantics remains authenticated but yields
a non-affirming policy result. Recognized type names are retained when evidence
is normalized for CoMID appraisal.

Strict version/type alignment is the default. A signed member policy may select
`known-types` to accept measurement types already understood by this verifier
when their encoding is newer than the negotiated SPDM version. This mode does
not accept unknown types or relax measurement-specification, raw/digest,
reserved-index, authentication, identity, or reference-value checks. Appraisal
reports state when the mode was used; it is an interoperability policy and not
a claim that the Evidence conforms to the negotiated SPDM version.

The semantic registry includes the SPDM 1.3 type vocabulary for normalization
and unit testing, but this package does not yet accept SPDM 1.3 wire
transcripts. SPDM 1.3 request-context parsing and policy enablement require a
separate interoperability review.

This is an experimental interoperability backend pending differential review
against DMTF libspdm or a libspdm offline-verification API. It is not a general
SPDM implementation and does not perform live protocol negotiation, revocation,
or session establishment.