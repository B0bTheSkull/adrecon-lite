from adrecon import uac


def test_decode_normal_account():
    flags = uac.decode(512)
    assert "NORMAL_ACCOUNT" in flags


def test_decode_disabled_account():
    # NORMAL_ACCOUNT (512) | ACCOUNTDISABLE (2) = 514
    flags = uac.decode(514)
    assert "NORMAL_ACCOUNT" in flags
    assert "ACCOUNTDISABLE" in flags


def test_decode_empty():
    assert uac.decode(0) == []
    assert uac.decode(None) == []


def test_decode_string_input():
    flags = uac.decode("512")
    assert "NORMAL_ACCOUNT" in flags


def test_decode_invalid_string():
    assert uac.decode("not-a-number") == []


def test_asrep_roastable_true():
    # NORMAL_ACCOUNT (512) | DONT_REQ_PREAUTH (4194304) = 4194816
    assert uac.asrep_roastable(4194816)


def test_asrep_roastable_false():
    assert not uac.asrep_roastable(512)


def test_password_never_expires():
    # 512 | DONT_EXPIRE_PASSWORD (65536) = 66048
    assert uac.password_never_expires(66048)
    assert not uac.password_never_expires(512)


def test_trusted_for_delegation():
    # SERVER_TRUST_ACCOUNT (8192) | TRUSTED_FOR_DELEGATION (524288) = 532480
    assert uac.trusted_for_delegation(532480)


def test_trusted_to_auth_for_delegation():
    # WORKSTATION_TRUST_ACCOUNT (4096) | TRUSTED_TO_AUTH_FOR_DELEGATION (16777216) = 16781312
    assert uac.trusted_to_auth_for_delegation(16781312)


def test_password_not_required():
    # NORMAL_ACCOUNT (512) | PASSWD_NOTREQD (32) = 544
    assert uac.password_not_required(544)
    assert not uac.password_not_required(512)


def test_is_disabled():
    assert uac.is_disabled(514)
    assert not uac.is_disabled(512)
