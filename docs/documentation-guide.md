# Maintain the documentation

Operator documentation adapts The Good Docs Project's
[Core documentation template pack, Iron v1.6.0](https://gitlab.com/tgdp/templates/-/tree/v1.6.0).
The pack fits the project's need for an entry point, operating procedures,
configuration lookup, explanations, and failure diagnosis. Templates use MIT-0;
this attribution does not declare a license for this project's software.

## Choose the page type

| Template | Project pages | Content |
| --- | --- | --- |
| [README](https://gitlab.com/tgdp/templates/-/blob/v1.6.0/readme/template_readme.md) | Root README | Purpose, status, first use, docs, development |
| [How-to](https://gitlab.com/tgdp/templates/-/blob/v1.6.0/how-to/template_how-to.md) | Lab lifecycle, universal deployment | Goal, prerequisites, ordered actions, verification, related information |
| [Reference](https://gitlab.com/tgdp/templates/-/blob/v1.6.0/reference/template_reference.md) | Cluster configuration | Fields, defaults, limits, file behavior, CLI options |
| [Troubleshooting](https://gitlab.com/tgdp/templates/-/blob/v1.6.0/troubleshooting/template_troubleshooting.md) | Troubleshooting | Symptom, cause, resolution |
| [Concept](https://gitlab.com/tgdp/templates/-/blob/v1.6.0/concept/template_concept.md) | Architecture | Context, relationships, behavior, assumptions |

Adapt sections to the task. Remove template prompts and unused headings. Keep
README short; link detailed procedures. Distinguish current instructions,
design-only material, and historical evidence in the index. Preserve recorded
results rather than rewriting them as new acceptance claims.

## Write runnable commands

- State working directory, privileges, dependencies, and required artifacts.
- Use consistent examples: `dev`, `dev-node`, `dev-private`, `192.168.100.0/24`.
  Explain what readers substitute.
- Omit shell prompts and session-changing options. Avoid hidden variables shared
  across pasted blocks.
- Explain destructive consequences before deletion. State that source YAML and
  `.env` survive; never suggest purging them through lifecycle tools.
- Give observable results. Separate plan, provisioning, automated validation,
  and physical hardware testing still pending.
- Keep secrets out of examples, logs, and commits.
- Use `auto-cluster-rke2` for the project; preserve actual `autonomous-rke2`
  service names, paths, and protocol identifiers.

## Review changes

Check commands against script `--help` and implementation. Check local links,
heading anchors, defaults, limits, and implemented-versus-future behavior. Review
README commands whenever a detailed procedure changes.

Run relevant automated checks for changed behavior. Documentation-only work does
not require deleting/provisioning a real cluster. Report what was checked; claim
live deployment validation only when it actually ran.
