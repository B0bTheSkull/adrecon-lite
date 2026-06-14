"""LDAP connection wrapper for live AD queries.

Pulls a normalized list of records back as plain dicts so the rest of the tool
doesn't have to know about ldap3 types.
"""

from __future__ import annotations

import ssl
from typing import Optional

# These attribute names cover everything the findings module checks.
USER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "servicePrincipalName",
    "memberOf",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "pwdLastSet",
    "lastLogonTimestamp",
    "description",
]


def _entry_to_dict(entry) -> dict:
    """Convert an ldap3 Entry to a plain dict, unwrapping single-value lists."""
    d: dict = {}
    for attr_name in entry.entry_attributes:
        val = entry[attr_name].value
        d[attr_name] = val
    return d


def fetch_records(
    server: str,
    user: str,
    password: str,
    base_dn: str,
    search_filter: str = "(&(objectCategory=person)(objectClass=user))",
    attributes: Optional[list[str]] = None,
    use_ssl: bool = False,
    insecure: bool = False,
) -> list[dict]:
    """Connect to an AD LDAP server and return a list of user records.

    When ``use_ssl`` is set (LDAPS) the server certificate is validated against
    the system trust store by default. Pass ``insecure=True`` to skip
    validation (e.g. self-signed lab DCs) — this disables protection against
    man-in-the-middle attacks and should not be used in production.
    """
    import ldap3  # imported lazily so tests/offline mode don't require ldap3

    tls = None
    if use_ssl:
        # Default to validating the DC certificate; LDAPS without validation
        # offers no MITM protection.
        validate = ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED
        tls = ldap3.Tls(validate=validate)

    server_obj = ldap3.Server(server, use_ssl=use_ssl, tls=tls, get_info=ldap3.ALL)
    conn = ldap3.Connection(
        server_obj,
        user=user,
        password=password,
        authentication=ldap3.NTLM if "\\" in user else ldap3.SIMPLE,
        auto_bind=True,
    )
    try:
        # Normalize bare conjuncts (e.g. "(a=b)(c=d)") into a valid AND group.
        if not search_filter.startswith("(&"):
            inner = search_filter
            if inner.startswith("(") and inner.endswith(")") and inner.count("(") == 1:
                # A single simple clause like "(objectClass=user)" — leave as-is.
                pass
            else:
                search_filter = f"(&{inner})"
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            attributes=attributes or USER_ATTRS,
        )
        return [_entry_to_dict(e) for e in conn.entries]
    finally:
        conn.unbind()
