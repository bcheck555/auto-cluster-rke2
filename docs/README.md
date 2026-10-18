# Documentation

Start with [create a libvirt cluster](lab-lifecycle.md) if you have a signed
universal image. Use [deploy the universal image](universal-node.md) for another
hypervisor or physical hardware. Both workflows use the same image on all nodes.

## Deployment and operation

| Goal | Document |
| --- | --- |
| Understand the project and run short create/rebuild commands | [Project README](../README.md) |
| Check prerequisites; create, inspect, restart, or destroy a VM cluster | [Lab lifecycle](lab-lifecycle.md) |
| Look up YAML fields, private inputs, CLI options, and resource names | [Configuration reference](cluster-config.md) |
| Diagnose configuration, discovery, and restart failures | [Troubleshooting](troubleshooting.md) |
| Change total nodes or control/worker mix | [Scaling](scaling.md) |
| Supply identity, networking, and enrollment to VM or physical clones | [Universal deployment](universal-node.md) |
| Build, validate, sign, publish, and export images | [Offline image workflow](offline-images.md) |
| Check what the universal image has actually passed | [Universal image validation](universal-image-results.md) |
| Check scaling-image artifacts and acceptance coverage | [Scaling image validation](scaling-image-results.md) |

## Explanations and engineering references

| Topic | Document |
| --- | --- |
| Components, locations, enrollment, and restart behavior | [Architecture](architecture.md) |
| Why initial formation requires the first node to boot alone | [Discovery decision](discovery-decision.md) |
| Enrollment secrets, identity, and security boundaries | [Trust model](trust-and-threat-model.md) |
| Persisted identity and journal contracts | [Durable state](durable-state.md) |
| Formation states | [State machine](state-machine.md) |
| Implementation progress | [Roadmap](roadmap.md) |
| Outstanding validation and design work | [Open questions](open-questions.md) |
| Possible recovery procedures; **design only, not executable** | [Recovery design](recovery-runbooks.md) |
| Documentation structure and template sources | [Documentation guide](documentation-guide.md) |

## Historical records and design material

These documents preserve earlier decisions and evidence. They do not replace
current universal-image deployment instructions. The external authority prototype
and separate-role images are not required for current boot.

| Record | Scope |
| --- | --- |
| [Bootstrap authority](bootstrap-authority.md) | External-authority prototype, retained for library/test reference |
| [Host agent](host-agent.md) | Earlier authority-backed lifecycle |
| [Component contracts](component-contracts.md) | Implementation blueprint; distinguish proposed contracts from current architecture |
| [Environment assessment](environment-assessment.md) | Host inventory at assessment time |
| [Phase 1 proposal](phase1-lab-proposal.md) | Earlier approved topology and host effects |
| [Phase 1 results](phase1-lab-results.md) | Evidence for the earlier lab |
| [Offline image results](offline-image-results.md) | Separate-role image and replacement evidence |
| [RKE2 version and operations](rke2-version-and-operations.md) | Release selection research and validation criteria |
| [Rocky-to-RHEL portability](rocky-to-rhel9.md) | Portability ledger; not a supported migration procedure |

If a historical procedure conflicts with a current guide, use the current guide
and inspect the implementation before changing a running cluster.
