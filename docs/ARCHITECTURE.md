# Architecture (Conceptual)

```
[Initial Access] -> [Recon/Discovery] -> [Prioritization/Targeting] -> [Execution/Impact]
                        |                         |
                        v                         v
                 [Data Selection]           [Extortion/Nego Bot]
```

## Modules (Hypothetical)
- Reconnaissance: Inventory assets, classify by criticality.
- Prioritization: Rank targets by business risk and blast radius.
- Execution: Living-off-the-land tools to minimize binaries.
- Negotiation: Guardrailed AI assistant (conceptual) for comms.

## Defensive Choke Points
- Email/Web gateways, EDR behavior rules, identity MFA/JIT, network segmentation, immutable backups.

## Variant Note: Non-Financial Autonomous Agents (defender view)

A defender-facing note on a variant of the base concept. It describes the threat class and its defensive implications only; it does not extend the base architecture with new attack capabilities.

- **No financial objective, no negotiation.** In this variant, there is no ransom logic and no payment flow. Defenders should not assume a financial motive or a negotiation phase: there is no payment event to detect, stall, or interdict, and no decryption key to recover.
- **Edge inference as a detection problem.** If the AI component runs on-device as a quantized model in the ~7B-parameter class, defenders lose the network telemetry that cloud inference would otherwise produce — no API calls to monitor, no remote cutoff to invoke. Detection shifts to on-device behavior: unauthorized model runtimes, weights loading outside approved paths, and anomalous process execution.
- **Staged operations as a hunting problem.** When an operation is split into independent stages (loader and payload), clearing one stage does not clear the other. Hunt loader persistence and payload execution as separate footholds, and triage loader detections on their own severity — a loader associated with destructive wiper activity should be treated as a wiper event regardless of what later stages do.

### Variant Defensive Choke Points (additive to the base list)

- On-device behavioral rules for unauthorized model runtimes and weights.
- Independent hunting of each operation stage; no stage assumed neutralized because another was removed.
- Wiper-pattern triage for destructive loader detections, without waiting for later stages to declare themselves.
- Egress and segmentation controls still apply, but cloud-AI telemetry must not be assumed present.
