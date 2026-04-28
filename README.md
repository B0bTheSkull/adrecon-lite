# ADRecon-Lite

> **Lightweight Active Directory enumeration and dangerous-config detector — finds AS-REP roastable accounts, Kerberoastable users, unconstrained / constrained / RBCD delegation, password-not-required accounts, and stale "password never expires" admins.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-alpha-orange?style=flat-square)

---

## What It Does

ADRecon-Lite is a focused, reviewable AD audit tool. It connects to a domain controller over LDAP, pulls user and computer records, and flags the configurations attackers actually look for during enumeration:

| Detection | Severity | Why it matters |
|---|---|---|
| **AS-REP roasting candidate** | high | `DONT_REQ_PREAUTH` set — TGT can be requested without preauthentication and offline cracked |
| **Kerberoastable user** | high | User account with `servicePrincipalName` set — service ticket can be requested and offline cracked |
| **Unconstrained delegation** | critical (medium on DC) | Captured TGTs from any user authenticating to this host can be reused anywhere |
| **Constrained delegation** | medium | Account can impersonate users to specific services |
| **Constrained delegation w/ protocol transition** | high | Same, but bypasses the requirement for the user to authenticate first |
| **Resource-based constrained delegation (RBCD)** | high | `msDS-AllowedToActOnBehalfOfOtherIdentity` populated — RBCD attack vector |
| **Password not required** | critical | Account can authenticate with empty password |
| **Password never expires** | low | Common on legacy admin accounts — credential rotation not happening |

Disabled accounts are filtered automatically — a stale config on a disabled account isn't an attack surface.

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/adrecon-lite.git
cd adrecon-lite
pip install -e .
```

---

## Usage

### Live AD scan

```bash
adrecon \
  --server ldap://dc01.lab.local \
  --user 'LAB\\analyst' \
  --base-dn 'DC=lab,DC=local'
# (you'll be prompted for password; or pass --password '...')
```

Use LDAPS:

```bash
adrecon --server ldaps://dc01.lab.local --ssl --user ... --base-dn ...
```

### Offline mode (for testing, demos, or CI)

```bash
adrecon --offline --records examples/sample_records.json
```

### JSON output for SOAR / pipeline ingestion

```bash
adrecon --offline --records examples/sample_records.json --json > audit.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No critical or high findings |
| `1` | At least one critical or high finding |
| `2` | Configuration / connectivity error |

---

## Example Output

```
ADRecon-Lite
Records inspected: 10  |  Findings: 8

────────────────────────────────────────────────────────────────────────
[CRITICAL] Password not required
  account: broken_kiosk
  dn:      CN=broken_kiosk,OU=Kiosks,DC=lab,DC=local
  detail:  PASSWD_NOTREQD set — account can authenticate with empty password
────────────────────────────────────────────────────────────────────────
[    HIGH] AS-REP roasting candidate
  account: legacy_app
  dn:      CN=legacy_app,OU=Service Accounts,DC=lab,DC=local
  detail:  DONT_REQ_PREAUTH set — TGT can be requested without pre-auth and offline cracked
────────────────────────────────────────────────────────────────────────
[    HIGH] Kerberoastable user
  account: svc_sql
  dn:      CN=svc_sql,OU=Service Accounts,DC=lab,DC=local
  detail:  User account has SPN(s) registered: MSSQLSvc/sql01.lab.local:1433
  spns: ['MSSQLSvc/sql01.lab.local:1433']
────────────────────────────────────────────────────────────────────────
[    HIGH] Constrained delegation with protocol transition
  account: iis_pool$
  dn:      CN=iis_pool,OU=Servers,DC=lab,DC=local
  detail:  Allowed to delegate to: http/intranet.lab.local
────────────────────────────────────────────────────────────────────────
...

Summary: [CRITICAL] 1  [    HIGH] 4  [  MEDIUM] 2  [     LOW] 1
```

---

## Why I Built This

Most enterprise SOC roles touch Windows / Active Directory in some form. The bigger AD recon tools (BloodHound, ADRecon, PingCastle) are excellent and worth knowing — but they're enormous. I wanted a smaller tool I could fully reason about, demo against a home lab, and use as a teaching aid for *why* each of these AD configurations is dangerous.

The offline mode is intentional: it means you can review the tool, run the test suite, and demo it without setting up a domain controller. Pair it with a free Windows Server 2019 evaluation VM (or a [GOAD lab](https://github.com/Orange-Cyberdefense/GOAD)) for the live story.

---

## Setting Up a Test Environment

For practicing against a real AD, the easiest options are:

- **GOAD (Game Of Active Directory)** — pre-built vulnerable AD lab: https://github.com/Orange-Cyberdefense/GOAD
- **Windows Server 2019/2022 evaluation** — free 180-day trial, install AD DS role, create a few test users with the dangerous flags
- **Detection Lab** — https://github.com/clong/DetectionLab

---

## Roadmap

- [ ] Group enumeration (Domain Admins, Enterprise Admins, Schema Admins, Account Operators)
- [ ] GPO enumeration with security-relevant settings (LSA protection, SMB signing, NTLM)
- [ ] Password policy retrieval (minimum length, complexity, lockout threshold)
- [ ] Stale account detection via `lastLogonTimestamp` (no logon in N days)
- [ ] Domain trust enumeration
- [ ] HTML report output for engagement deliverables
- [ ] Output that BloodHound can ingest

---

## License

MIT — see [LICENSE](LICENSE)
