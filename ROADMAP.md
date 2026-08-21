# ForgeWarden Roadmap

## Current implementation priority

ForgeWarden Core remains the active implementation mission. The broader security-platform expansion is approved and must remain architecturally compatible, but should not displace Core work unless the active phase explicitly requires a future-facing interface or schema.

## Core trust model

- Hermes is the user-facing front door.
- Codex is the sole application-code writer.
- Claude provides architecture, requirements, threat-model, and adversarial review.
- Gemini performs independent read-only exact-commit review.
- The trusted Python orchestrator owns deterministic validation, hashes, paths, Git, limits, audit, cleanup, state, deployment controls, and rollback.
- Jeff / Customer Root retains activation authority and all authority expansion.
- `DRY_RUN` remains enforced; deployment remains disabled until explicitly authorized.
- Product principle: **autonomous security without autonomous authority**.

## Active / foundational requirement families

### FW-ROOT — Root authority and deterministic policy
Customer Root, Z3 Policy Engine/Action Broker, signed policies, bounded leases/capabilities, single-use Action Tickets, dual control, kill-switch enforcement, immutable prohibitions, and machine-checkable invariants.

### FW-ID — Identity and authority
Tenant-bound identity schema; human and non-human identities; device trust; passkeys/WebAuthn; PIV/CAC; TOTP/HOTP fallback; OIDC/SAML federation; break-glass; risk; lifecycle; identity-device binding; audit; service accounts; API keys; OAuth apps; service principals; workload/Kubernetes/MCP/AI-agent identities with owner, purpose, permissions, usage baseline, expiration, rotation, and revocation.

### FW-KEYS — Secrets, certificates, PKI and HSM
Separate customer root, identity CA, workload/service CA, Z3 Action Ticket signing, Evidence signing, Recovery authority/encryption, vendor release signing, threat-intel/model approval intermediates, hardware-backed/non-exportable roots where practical, per-tenant encryption domains, secret handles, rotation, backup/escrow and HSM/TPM/Secure Enclave integration.

### FW-EVID — Evidence and immutable audit
Signed, versioned evidence records; append-only audit; exact action provenance; chain-of-custody; incident evidence retention; integrity verification; export/reporting interfaces.

### FW-REC — Recovery and rollback
Verified recovery metadata, protected snapshots, bounded rollback, integrity checks, recovery authority separation, destructive-action dual control, and deterministic restoration validation.

### FW-TEST — Continuous validation and invariants
Unit/integration/security tests; deterministic simulation; policy/rule tests; formal models where practical; AV/RansomGuard/identity/Z3/NAC/DLP/Recovery/Evidence/AI/MCP/HA/rollback coverage; exact-commit validation.

## Broader approved security roadmap

### FW-ENDPOINT — Endpoint Detection and Response
Cross-platform MicroSensors for Windows/Linux/macOS plus WSL2 inventory/telemetry; IOAs; process/file/network/runtime correlation; containment; Protection Impact Monitoring; bounded resource use; mobile coverage for managed iOS/iPadOS/Android.

### FW-AV — Native anti-malware
On-access/execution and scheduled scanning; hash/reputation; signatures/publisher trust; YARA/content; archive/document/script analysis; memory/process indicators; sandbox escalation; performance caches.

### FW-RANSOM — RansomGuard
Canaries; mass write/rename/delete detection; entropy/extension/ransom-note/shadow-copy/credential/service tamper signals; SMB propagation/lateral movement; automated bounded isolate/block/freeze/snapshot/rollback workflows with dual control for destructive steps.

### FW-MCP — Model Context Protocol security gateway
Operate as approved MCP host/client and minimal MCP server; registry; discovery; trust levels; capability policy; identity; approval gates; credential isolation; rate/resource limits; sanitization; immutable audit; replay protection; health; kill switch; no arbitrary shell/filesystem/Git/env/deployment bypass.

### FW-API — Versioned least-privilege API/SDK
Typed interfaces; tenant binding; identity; leases; Z3 authorization; signed single-use Action Tickets for mutation; strict audit and compatibility policy.

### FW-OPS — Operations, HA/DR and observability
No single points of failure; quorum/consensus where needed; active/active or active/standby patterns; update rollback; OpenTelemetry; workload isolation; capacity/backpressure; hot/warm retention tiers; separate operational telemetry from Evidence Vault.

### FW-UX — Mission Control
Role-aware interfaces for small business owner/admin, SOC analyst, Security Admin, Recovery Officer, Auditor/Compliance, Root Admin, MSSP and government/high-assurance users. Include unified incidents, approval workflows, evidence, recovery, health and policy state.

### FW-GOV — Government/high-assurance controls
Per-model Authorization Gate by boundary/data class/ATO/FedRAMP/DoD IL; deterministic Approved Model Registry and Model Broker; failover only to approved equivalents; no opaque router LLM in government mode; support sovereign/air-gapped deployment.

### FW-BME — Browser, Messaging and Email Protection
Managed Chrome/Edge/Firefox policy; extension allow-listing and risk monitoring; malicious/phishing domain, exploit site, dangerous download, redirect and notification-abuse controls; browser-to-local-process/script controls; browser credential-store, cookie/session/token theft and replay detection; OAuth-consent abuse; session quarantine/revocation; high-risk browser isolation; SPF/DKIM/DMARC; phishing/spoofing/look-alike/display-name/BEC detection; QR phishing; HTML smuggling; macro/script/archive/PDF/Office analysis; time-of-click link inspection; Detonation Chamber integration; browser/email DLP; prompt-injection defenses; Z3-backed containment.

### FW-SOC — Security Operations, SIEM, SOAR and Case Management
Security data lake/SIEM for ForgeWarden and third-party telemetry; normalization to ForgeWarden event schema; cross-domain correlation into attack stories; bounded Security Response Playbook Engine integrated with Z3 and signed Action Tickets; case timelines, affected assets/identities, evidence, approvals, recovery and final disposition.

### FW-SAAS — SaaS Security Posture and SaaS Threat Defense
Discover sanctioned/shadow SaaS; users, guests, OAuth apps, API tokens, service principals, integrations and permissions; detect misconfiguration, excessive privilege, dormant accounts, public shares, suspicious logins, risky OAuth consent, unsafe third-party apps and AI applications accessing company data.

### FW-SUPPLY — Application and Software Supply-Chain Security
Code-to-runtime protection for repositories, developer systems, dependencies, CI/CD, builds, containers, IaC, deployment and runtime; SAST; SCA; malicious package/typosquatting/dependency-confusion detection; secret scanning; SBOM; container/IaC scanning; CI/CD integrity; provenance; signed builds/releases; attestations; FW-KEYS integration.

### FW-NET — Network Detection, Response and Zero Trust
DNS, DHCP, TLS, SMB, RDP, SSH, LDAP, Kerberos, HTTP/S, VPN, Wi-Fi, east-west/north-south and network-device telemetry; scan/lateral-movement/C2/credential-abuse/exfiltration detection; identity-based NAC; guest/contractor access; segmentation; device trust; Z3 enforcement.

### FW-ASM — External Attack Surface Management
Continuous discovery of domains, subdomains, public IPs, cloud resources, VPN endpoints, ports, websites, APIs, remote-access systems, certificates, DNS, forgotten assets, exposed databases and development systems; reconcile externally visible assets with CMDB; evaluate exposure, ownership, exploitability and attack paths.

### FW-DSPM — Data Security Posture Management
Discover and classify sensitive data across endpoints, browser/email, SaaS, cloud, databases, repositories and AI workflows; track owner, access paths, copies, encryption, AI/agent access and exfiltration policy; integrate DLP with identity, evidence, SOC and Z3.

## Additional approved platform capabilities

- Threat Hunter, Identity Protection, Attack-Path Graph, Detonation Chamber, Forensic Timeline, Data-Movement Protection, AI/Prompt-Injection Defense and Threat-Intelligence Gateway.
- Asset Discovery/CMDB/Config Integrity across endpoints, servers, VMs, WSL2, containers, cloud, mobile, network, apps, services, databases, repositories, models, MCP servers, identities, certificates, packages, owners and dependencies.
- Vulnerability/Patch Management correlated with CVEs, exploit availability, exposure, privilege, criticality and threat intelligence.
- Browser/email and AI-delivered hostile content always treated as untrusted data, never agent authority.
- Deception/honeypot capabilities: decoy credentials, accounts, SMB shares, files, API keys, databases and service identities as high-confidence signals.
- Integration/coexistence with incumbent EDR, SIEM, IAM, firewall, cloud, ticketing and IT/security tools through versioned connectors/APIs/MCP so customers can adopt incrementally.
- Strict multi-tenant isolation with no cross-tenant analytics and no universal admin/support bypass.
- Standards-readiness alignment: NIST CSF 2.0, NIST 800-53/171/172, ISO 27001/27017/27018, SOC 2, CIS, CMMC, HIPAA/HITECH and PCI DSS.

## Phase discipline

Future requirement families remain documented and interface-compatible, but implementation follows the active phase and `WORK_QUEUE.md`. No agent may begin broad platform expansion simply because a requirement appears here.
