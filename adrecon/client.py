"""LDAP connection wrapper for live AD queries.

Pulls a normalized list of records back as plain dicts so the rest of the tool
doesn't have to know about ldap3 types.
"""

from __future__ import annotations

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
    search_filter: str = "(objectCategory=person)(objectClass=user)",
    attributes: Optional[list[str]] = None,
    use_ssl: bool = False,
) -> list[dict]:
    """Connect to an AD LDAP server and return a list of user records."""
    import ldap3  # imported lazily so tests/offline mode don't require ldap3

    server_obj = ldap3.Server(server, use_ssl=use_ssl, get_info=ldap3.ALL)
    conn = ldap3.Connection(
        server_obj,
        user=user,
        password=password,
        authentication=ldap3.NTLM if "\\" in user else ldap3.SIMPLE,
        auto_bind=True,
    )
    try:
        if not search_filter.startswith("("):
            search_filter = f"(&{search_filter})"
        conn.search(
            search_base=base_dn,
            search_filter=search_filter if search_filter.startswith("(&") else f"(&{search_filter})",
            attributes=attributes or USER_ATTRS,
        )
        return [_entry_to_dict(e) for e in conn.entries]
    finally:
        conn.unbind()
