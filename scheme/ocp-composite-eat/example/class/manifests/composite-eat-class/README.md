# Platform Composite EAT Class Authoring Templates

This directory contains vendor-neutral source templates for the experimental
Platform CoRIM class model `0.5.0`:

- `platform-class.json` defines one reusable platform family, two variants,
  required component roles, and Lead reference values.
- `component-class.json` defines one reusable component class and reference set.
- `enrollments.example.json` shows the separate per-server identity assignment.
- `platform-corim-meta.json` and `component-corim-meta.json` are upstream
  `cocli` signing metadata templates.

These files contain synthetic values only. They are authoring examples, not
signed endorsements or production enrollment. Replace values from independently
approved inventory, release and manufacturing sources. Never promote values from
the Evidence currently being appraised into trusted references or enrollment.

Run the complete generated example from the repository root:

```bash
make composite-eat-example
```

For manual export, signing, package assembly and verifier configuration, follow
the [adopter runbook](../../../../docs/adopter-runbook.md). The example
writes generated keys, certificates, CoRIMs, Evidence and reports only under the
ignored `scheme/ocp-composite-eat/example/class/.example-output` directory.
