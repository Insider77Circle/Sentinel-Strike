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

## Variant: Edge-Autonomous (non-financial, staged, edge inference)

A design variant of the base concept, documented at the same hypothetical level. Three changes from the base architecture:

- **No negotiation module, no financial objective.** The Extortion/Nego Bot module is removed entirely. This variant has no ransom logic and no payment flow; its objective is non-financial. The base concept's double-extortion goals do not apply to this variant.
- **Edge inference.** The AI component is a quantized model in the ~7B-parameter class, sized to run on edge devices. No cloud inference dependency: no API telemetry trail and no remote cutoff. Capability is narrower than a frontier model, but sufficient for the recon, targeting, and prioritization roles in this architecture.
- **Staged delivery.** SentinelStrike rides as a stage 2 process. Stage 1 is a modified Petya lineage loader whose injection function is repurposed to deliver stage 2. The stages are independent: neutralizing one does not neutralize the other.

Revised flow:

[Stage 1 Loader] -> [Stage 2: SentinelStrike] -> [Recon/Discovery] -> [Prioritization/Targeting] -> [Execution/Impact]
                                                                          |
                                                                          v
                                                                   [Data Selection]

### Variant Defensive Choke Points (additive to the base list)

- On-device behavioral detection: edge inference removes the network telemetry defenders would otherwise see from cloud model calls; detection shifts to on-device process, execution, and persistence behavior.
- Stage-1-as-wiper treatment: a Petya-lineage loader reads as destructive wiper activity on detection, regardless of stage 2's behavior; triage should not wait for stage 2 to declare itself.
- Hunt both stages independently: loader persistence and stage 2 execution are separate footholds; clearing one without the other leaves the chain intact.
- Edge-model artifacts: hunt for local model runtimes and weights loading outside approved application paths.
