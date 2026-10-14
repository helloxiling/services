# Platform Composite EAT Class Example

This vendor-neutral example demonstrates one shared Platform class CoRIM, one
shared component reference CoRIM, and two separately enrolled servers. It uses
the same `ClassProvider` in offline appraisal and the Veraison service.

Run the complete flow from the repository root:

```bash
make composite-eat-example
```

The command:

1. generates temporary demonstration authorities and two synthetic bundles;
2. packages and signs class sources with the pinned upstream `cocli` binary;
3. writes artifacts only under ignored `.example-output/class`;
4. verifies two positive and two negative scenarios offline;
5. deploys Veraison with class mode enabled;
6. submits all scenarios through the challenge-response API;
7. authenticates the advertised EAR key and checks each EAR nonce and status;
8. stops the demonstration services on exit.

Expected service results:

| Scenario | Result |
|---|---|
| `server-0-good` | affirming |
| `server-1-good` | affirming |
| `server-0-cross-server` | non-affirming |
| `server-1-missing-required` | non-affirming |

The generated authorities, enrollment, reference values, Evidence and TLS setup
are synthetic. The example proves integration behavior, not current hardware
liveness, production trust, or standards conformance. Platform CoRIM conceptual
model `0.5.0` remains experimental.

See the [adopter runbook](../../docs/adopter-runbook.md)
for tracked templates and production authoring, signing, enrollment and rollout
requirements.