"""Parsing and inspection of the Active Directory userAccountControl bitmask.

Reference:
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
"""

# Most-significant flags. Full list is much longer; these are the security-relevant ones.
UAC_FLAGS: dict[int, str] = {
    0x00000001: "SCRIPT",
    0x00000002: "ACCOUNTDISABLE",
    0x00000008: "HOMEDIR_REQUIRED",
    0x00000010: "LOCKOUT",
    0x00000020: "PASSWD_NOTREQD",
    0x00000040: "PASSWD_CANT_CHANGE",
    0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x00000100: "TEMP_DUPLICATE_ACCOUNT",
    0x00000200: "NORMAL_ACCOUNT",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT",
    0x00002000: "SERVER_TRUST_ACCOUNT",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00020000: "MNS_LOGON_ACCOUNT",
    0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION",
    0x00100000: "NOT_DELEGATED",
    0x00200000: "USE_DES_KEY_ONLY",
    0x00400000: "DONT_REQ_PREAUTH",  # AS-REP roastable
    0x00800000: "PASSWORD_EXPIRED",
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}


def decode(uac: int | str | None) -> list[str]:
    """Return the list of flag names set in a userAccountControl integer."""
    if uac is None:
        return []
    if isinstance(uac, str):
        try:
            uac = int(uac)
        except ValueError:
            return []
    return [name for bit, name in UAC_FLAGS.items() if uac & bit]


def has_flag(uac: int | str | None, flag_name: str) -> bool:
    return flag_name in decode(uac)


def is_disabled(uac: int | str | None) -> bool:
    return has_flag(uac, "ACCOUNTDISABLE")


def password_never_expires(uac: int | str | None) -> bool:
    return has_flag(uac, "DONT_EXPIRE_PASSWORD")


def asrep_roastable(uac: int | str | None) -> bool:
    return has_flag(uac, "DONT_REQ_PREAUTH")


def trusted_for_delegation(uac: int | str | None) -> bool:
    return has_flag(uac, "TRUSTED_FOR_DELEGATION")


def trusted_to_auth_for_delegation(uac: int | str | None) -> bool:
    """Constrained delegation (with protocol transition)."""
    return has_flag(uac, "TRUSTED_TO_AUTH_FOR_DELEGATION")


def password_not_required(uac: int | str | None) -> bool:
    return has_flag(uac, "PASSWD_NOTREQD")
