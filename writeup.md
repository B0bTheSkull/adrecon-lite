# Reading an AD environment before the defenders do

> Active Directory is not a place attackers break into. It's a place they walk through — after they already have a foothold — and collect keys. The question is whether you enumerated it first.

## TL;DR

ADRecon-Lite is a Python CLI I built to enumerate Active Directory user and computer accounts over LDAP and flag the configurations that actually show up in kill chains: AS-REP roastable accounts, Kerberoastable service accounts, unconstrained and constrained delegation, RBCD, empty-password accounts, and stale never-expire admins. On the bundled 10-record sample it finds 8 findings — 1 critical, 4 high — in under a second. An offline mode lets you demo and test it without a live domain controller.

---

## Why bother

Every internal pentest I've studied hits the same playbook once initial access is established: enumerate AD, find a path to Domain Admin. The tool that usually does this is BloodHound — it's excellent, it's the industry standard, and it's also a 200 MB Electron app with a Neo4j backend that requires a separate ingestor, a running database, and a UI to read results. That's the right tool for a full engagement. It's a heavy dependency for learning or for a quick "what's obviously wrong in here" audit.

The tools that exist on the other end of the spectrum are largely scripts that dump everything and leave the analysis to you.

I wanted something in between: small enough that I can read the entire source in an afternoon, focused enough that it only surfaces findings that matter to an attacker, and designed so the output can feed a pipeline (`--json`, exit codes) instead of requiring a human to parse it. The offline mode is the other half of the motivation — being able to run the test suite, demo the tool, or review what it catches without needing to stand up a Windows domain made the build and iteration loop much faster.

## What's actually new about this build

The AD recon tooling space is not empty. What I tried to do differently:

1. **Focused, not exhaustive.** ADRecon-Lite targets eight specific finding types — the ones that appear most frequently in writeups of real AD compromises. It doesn't try to be a full AD auditor. You don't get GPO analysis, password policy retrieval, or trust enumeration from this tool (those are on the roadmap, but not shipped).

2. **Offline-first design.** The `--offline` flag and bundled `examples/sample_records.json` mean you can review, test, and demo the tool without LDAP credentials or a domain controller. The test suite (`tests/`) runs entirely offline. This was a deliberate tradeoff — it meant I could iterate quickly and keep the CI simple.

3. **Machine-readable output.** `--json` emits a structured payload; exit code `1` means critical or high findings present. Both are designed to plug into a SOAR or a simple `if [ $? -eq 1 ]` check in a pipeline.

4. **Honest about the UAC bitmask.** The `uac.py` module is a standalone decoder for the `userAccountControl` integer that AD returns. It's documented against the Microsoft reference, it handles string inputs gracefully, and the logic is separate from the detection logic so it can be tested in isolation.

## Architecture

```
adrecon/
├── cli.py          # argparse wiring, mode dispatch
├── client.py       # LDAP connection and record fetch (live mode)
├── findings.py     # one function per finding type; find_all() aggregates
├── uac.py          # userAccountControl bitmask decoder
└── output.py       # text (with ANSI color) and JSON formatters
```

The path through the code for a live scan:

```
cli.main()
  → client.fetch_records(server, user, password, base_dn)   # LDAP bind + search
  → findings.find_all(records)                              # 7 detection passes
  → output.print_text() / print_json()                     # formatted output
```

Each detection function in `findings.py` gets the full record list, filters disabled accounts, checks the relevant UAC flags or LDAP attributes, and returns `Finding` dataclasses. `find_all()` chains them and sorts by severity. Nothing stateful; no global mutable state.

The LDAP query requests a fixed attribute set: `sAMAccountName`, `distinguishedName`, `userAccountControl`, `servicePrincipalName`, `msDS-AllowedToDelegateTo`, and `msDS-AllowedToActOnBehalfOfOtherIdentity`. That's all the tool needs. Smaller query, less noise.

## Things that bit me

### The UAC bitmask is an integer, except when LDAP hands it to you as a string

The `ldap3` library returns most attributes as strings when you use certain response formats. `userAccountControl` comes back as `"512"` not `512`. The bitmask logic needs `int & int`. I spent longer than I'd like on a test that was producing zero findings — every `has_flag()` call returning `False` — before tracing it to a string/int mismatch. `uac.py` now coerces to int early and handles the failure case explicitly.

### Unconstrained delegation on DCs looks scary but is expected

Every domain controller has `TRUSTED_FOR_DELEGATION` set. That's by design — the DC needs to be able to forward Kerberos tickets on behalf of users. A naive check flags every DC as critical unconstrained delegation. The tool now inspects the `distinguishedName` for `OU=Domain Controllers` and downgrades those findings to medium with a `(DC — expected)` note. Still worth knowing; not worth paging on at 2 AM.

### Kerberoastable computer accounts are not interesting

Computer accounts can have SPNs registered — that's normal. The interesting case is a *user* account with an SPN, because those tend to have human-chosen passwords that can be cracked offline. The `find_kerberoastable` check explicitly requires `NORMAL_ACCOUNT` in the UAC flags before flagging. Computer accounts have `WORKSTATION_TRUST_ACCOUNT` or `SERVER_TRUST_ACCOUNT` instead.

## Real output against the sample data

The tool ships with `examples/sample_records.json` — 10 records with a range of configurations, including a clean user, a disabled account with bad flags (which correctly produces no findings), and accounts representing each finding type.

```
$ adrecon --offline --records examples/sample_records.json --no-color

ADRecon-Lite
Records inspected: 10  |  Findings: 8

────────────────────────────────────────────────────────────────────────────────
[CRITICAL] Password not required
  account: broken_kiosk
  dn:      CN=broken_kiosk,OU=Kiosks,DC=lab,DC=local
  detail:  PASSWD_NOTREQD set — account can authenticate with empty password
────────────────────────────────────────────────────────────────────────────────
[    HIGH] AS-REP roasting candidate
  account: legacy_app
  dn:      CN=legacy_app,OU=Service Accounts,DC=lab,DC=local
  detail:  DONT_REQ_PREAUTH set — TGT can be requested without pre-auth and offline cracked
────────────────────────────────────────────────────────────────────────────────
[    HIGH] Constrained delegation with protocol transition
  account: iis_pool$
  dn:      CN=iis_pool,OU=Servers,DC=lab,DC=local
  detail:  Allowed to delegate to: http/intranet.lab.local
────────────────────────────────────────────────────────────────────────────────
[    HIGH] Kerberoastable user
  account: svc_sql
  dn:      CN=svc_sql,OU=Service Accounts,DC=lab,DC=local
  detail:  User account has SPN(s) registered: MSSQLSvc/sql01.lab.local:1433
────────────────────────────────────────────────────────────────────────────────
[    HIGH] Resource-based constrained delegation
  account: rbcd_target$
  dn:      CN=rbcd_target,OU=Servers,DC=lab,DC=local
  detail:  msDS-AllowedToActOnBehalfOfOtherIdentity is populated — RBCD attack vector
────────────────────────────────────────────────────────────────────────────────
[  MEDIUM] Constrained delegation
  account: fileserver$
  dn:      CN=fileserver,OU=Servers,DC=lab,DC=local
  detail:  Allowed to delegate to: cifs/dc01.lab.local
────────────────────────────────────────────────────────────────────────────────
[  MEDIUM] Unconstrained delegation (DC — expected)
  account: DC01$
  dn:      CN=DC01,OU=Domain Controllers,DC=lab,DC=local
  detail:  TRUSTED_FOR_DELEGATION set — captured TGTs from any user authenticating to this host can be reused anywhere
────────────────────────────────────────────────────────────────────────────────
[     LOW] Password never expires
  account: old_admin
  dn:      CN=old_admin,OU=Admins,DC=lab,DC=local
  detail:  DONT_EXPIRE_PASSWORD set on a user account
────────────────────────────────────────────────────────────────────────────────

Summary: [CRITICAL] 1  [    HIGH] 4  [  MEDIUM] 2  [     LOW] 1

Exit code: 1
```

The disabled account (`disabled_old`) has `DONT_REQ_PREAUTH` set in its UAC value and still produces zero findings. That's the correct behavior — disabled accounts are not an attack surface.

The JSON mode produces the same data structured for pipeline consumption:

```bash
$ adrecon --offline --records examples/sample_records.json --json | jq '.findings[0]'
{
  "severity": "critical",
  "title": "Password not required",
  "sam_account_name": "broken_kiosk",
  "distinguished_name": "CN=broken_kiosk,OU=Kiosks,DC=lab,DC=local",
  "detail": "PASSWD_NOTREQD set — account can authenticate with empty password",
  "extra": {}
}
```

## Limits and what I'd add next

**No live AD to test against.** The output above is from the bundled sample data, not a live domain controller. The LDAP client code (`client.py`) is straightforward `ldap3` usage, but I haven't put it against a real DC yet. GOAD or a Windows Server eval VM is the right next step for that. I'm documenting the gap rather than pretending the tool is production-validated.

**Eight finding types, not twenty.** Group membership (Domain Admins, Enterprise Admins), GPO security settings, password policy, stale accounts by `lastLogonTimestamp`, and domain trust enumeration are all missing. They're on the roadmap. The current eight are the ones I'd want to see first on a real engagement.

**No authentication options beyond simple bind.** NTLM pass-the-hash, certificate-based auth, and Kerberos ticketing are all possible LDAP auth mechanisms that ADRecon-Lite doesn't support. For a tool that's supposed to work in pentest conditions, those are real gaps.

**The `--json` output currently exits with code 1 even for pipelines that just want the data.** That's arguably a design flaw — a consumer that only wants JSON for storage shouldn't have to handle a non-zero exit as an error. A `--no-exit-code` flag or a separate exit-code semantic would be cleaner.

## What I'd do differently

- **Build the test suite first.** The unit tests for `findings.py` and `uac.py` turned out to be the most useful debugging tool I had. I wrote them after the detection logic, which meant I caught several bugs late. Test-first would have been faster.
- **Make the sample records richer.** Ten records is enough to exercise every code path, but it's not enough to make the output feel realistic. A 50- or 100-record sample with plausible OUs, naming conventions, and a mix of clean accounts would tell a better story.
- **Run against GOAD before publishing.** I shipped before I had a live AD to validate against. That's a gap I should close before claiming the tool is anything beyond "demo-quality."

## Resources

- [Microsoft UAC flag reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties) — the canonical source for every bit in the bitmask
- [GOAD — Game Of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) — the easiest way to get a vulnerable lab AD without building one from scratch
- [Harmj0y's AS-REP roasting post](https://blog.harmj0y.net/activedirectory/roasting-as-reps/) — the writeup that made AS-REP roasting widely understood
- [The Hacker Recipes — Kerberos delegation](https://www.thehacker.recipes/ad/movement/kerberos/delegations) — the clearest reference I found for the three delegation types and why they matter
- The repo for this project: [github.com/B0bTheSkull/adrecon-lite](https://github.com/B0bTheSkull/adrecon-lite)
