# Threat Model (Conceptual)

## Adversary Goals
- Encrypt or deny access to high-value data and systems.
- Exfiltrate sensitive data for double extortion.

## Assumptions
- Mixed Windows/Linux estate, AD-joined endpoints, common SaaS.
- Standard EDR/AV present; backups exist with varying quality.

## Potential TTPs (MITRE ATT&CK Mapping)
- Initial Access: Phishing, Exploit Public-Facing App, Supply Chain.
- Execution: PowerShell, Command and Scripting Interpreter.
- Privilege Escalation: Exploitation for Privilege Escalation.
- Discovery: Network Service Scanning, Permission Groups Discovery.
- Lateral Movement: SMB/WinRM/PSExec equivalents.
- Exfiltration: Archive Collected Data, Exfiltration Over Web Services.
- Impact: Data Encrypted for Impact, Inhibit System Recovery.

## Defensive Controls & Detections
- Identity: MFA everywhere, JIT admin, disable legacy protocols.
- Endpoint: Application control, script logging, ASR rules.
- Network: Segmentation, egress controls, DNS logging.
- Data: Tiered/offline backups, FIM on critical paths.
- Detections: Burst encryption behavior, anomalous service creation, rapid toolchain switching.

## Variant: Edge-Autonomous (non-financial, staged, edge inference)

- **Adversary goals (variant):** non-financial. No ransom demand, no negotiation, no payment flow. Impact is pursued through autonomous operation, persistence, and replication rather than extortion leverage. The base goals — encryption for access denial and double extortion — do not apply to this variant.
- **Assumptions (variant, additive):** AI inference runs on-device via a quantized ~7B-parameter model (no cloud dependency); delivery is staged, with a modified Petya lineage loader as stage 1 delivering SentinelStrike as stage 2.
- **Additional TTP considerations:** staged delivery (loader/payload split); on-device model execution; self-replication as a persistence mechanism (per the base concept's self-healing capability).
- **Additional defensive controls & detections:** on-device behavioral rules for unauthorized model runtimes; stage-1 wiper-pattern triage; independent hunting of loader and payload persistence; egress controls still apply, but cloud-AI telemetry must not be assumed present.
