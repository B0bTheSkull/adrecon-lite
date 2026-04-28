"""Security finding detection over a normalized list of AD records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from adrecon import uac


@dataclass
class Finding:
    severity: str  # critical / high / medium / low
    title: str
    sam_account_name: str
    distinguished_name: Optional[str]
    detail: str
    extra: dict[str, Any] = field(default_factory=dict)


def _get(rec: dict, key: str, default=None):
    """LDAP records sometimes wrap single values in lists — normalize that."""
    v = rec.get(key, default)
    if isinstance(v, list):
        return v[0] if v else default
    return v


def find_asrep_roastable(records: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for r in records:
        u = _get(r, "userAccountControl")
        if uac.asrep_roastable(u) and not uac.is_disabled(u):
            out.append(
                Finding(
                    severity="high",
                    title="AS-REP roasting candidate",
                    sam_account_name=_get(r, "sAMAccountName", "(unknown)"),
                    distinguished_name=_get(r, "distinguishedName"),
                    detail="DONT_REQ_PREAUTH set — TGT can be requested without pre-auth and offline cracked",
                )
            )
    return out


def find_kerberoastable(records: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for r in records:
        u = _get(r, "userAccountControl")
        if uac.is_disabled(u):
            continue
        spns = r.get("servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        # Filter user accounts (NORMAL_ACCOUNT 0x200) — exclude computer accounts
        if not spns:
            continue
        if not uac.has_flag(u, "NORMAL_ACCOUNT"):
            continue
        out.append(
            Finding(
                severity="high",
                title="Kerberoastable user",
                sam_account_name=_get(r, "sAMAccountName", "(unknown)"),
                distinguished_name=_get(r, "distinguishedName"),
                detail=f"User account has SPN(s) registered: {', '.join(spns[:3])}",
                extra={"spns": spns},
            )
        )
    return out


def find_unconstrained_delegation(records: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for r in records:
        u = _get(r, "userAccountControl")
        if uac.is_disabled(u):
            continue
        if not uac.trusted_for_delegation(u):
            continue
        # Domain controllers are expected to have this flag — heuristic: filter by OU
        dn = _get(r, "distinguishedName", "") or ""
        is_dc = "OU=Domain Controllers" in dn
        out.append(
            Finding(
                severity="medium" if is_dc else "critical",
                title="Unconstrained delegation"
                + (" (DC — expected)" if is_dc else ""),
                sam_account_name=_get(r, "sAMAccountName", "(unknown)"),
                distinguished_name=dn,
                detail=(
                    "TRUSTED_FOR_DELEGATION set — captured TGTs from any user "
                    "authenticating to this host can be reused anywhere"
                ),
            )
        )
    return out


def find_constrained_delegation(records: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for r in records:
        u = _get(r, "userAccountControl")
        if uac.is_disabled(u):
            continue
        targets = r.get("msDS-AllowedToDelegateTo") or []
        if isinstance(targets, str):
            targets = [targets]
        if not targets:
            continue
        is_protocol_transition = uac.trusted_to_auth_for_delegation(u)
        out.append(
            Finding(
                severity="high" if is_protocol_transition else "medium",
                title="Constrained delegation"
                + (" with protocol transition" if is_protocol_transition else ""),
                sam_account_name=_get(r, "sAMAccountName", "(unknown)"),
                distinguished_name=_get(r, "distinguishedName"),
                detail=f"Allowed to delegate to: {', '.join(targets[:3])}",
                extra={"targets": targets, "protocol_transition": is_protocol_transition},
            )
        )
    return out


def find_rbcd(records: list[dict]) -> list[Finding]:
    """Resource-based constrained delegation."""
    out: list[Finding] = []
    for r in records:
        rbcd = r.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not rbcd:
            continue
        out.append(
            Finding(
                severity="high",
                title="Resource-based constrained delegation",
                sam_account_name=_get(r, "sAMAccountName", "(unknown)"),
                distinguished_name=_get(r, "distinguishedName"),
                detail="msDS-AllowedToActOnBehalfOfOtherIdentity is populated — RBCD attack vector",
            )
        )
    return out


def find_password_never_expires(records: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for r in records:
        u = _get(r, "userAccountControl")
        if uac.is_disabled(u):
            continue
        if not uac.has_flag(u, "NORMAL_ACCOUNT"):
            continue
        if uac.password_never_expires(u):
            out.append(
                Finding(
                    severity="low",
                    title="Password never expires",
                    sam_account_name=_get(r, "sAMAccountName", "(unknown)"),
                    distinguished_name=_get(r, "distinguishedName"),
                    detail="DONT_EXPIRE_PASSWORD set on a user account",
                )
            )
    return out


def find_password_not_required(records: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for r in records:
        u = _get(r, "userAccountControl")
        if uac.is_disabled(u):
            continue
        if uac.password_not_required(u):
            out.append(
                Finding(
                    severity="critical",
                    title="Password not required",
                    sam_account_name=_get(r, "sAMAccountName", "(unknown)"),
                    distinguished_name=_get(r, "distinguishedName"),
                    detail="PASSWD_NOTREQD set — account can authenticate with empty password",
                )
            )
    return out


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def find_all(records: list[dict]) -> list[Finding]:
    """Run every detection and return findings sorted by severity."""
    findings: list[Finding] = []
    for fn in (
        find_asrep_roastable,
        find_kerberoastable,
        find_unconstrained_delegation,
        find_constrained_delegation,
        find_rbcd,
        find_password_not_required,
        find_password_never_expires,
    ):
        findings.extend(fn(records))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.title))
    return findings
