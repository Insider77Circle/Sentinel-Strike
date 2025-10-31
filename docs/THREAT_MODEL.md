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
