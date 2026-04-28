import json
from pathlib import Path

from adrecon.findings import (
    find_all,
    find_asrep_roastable,
    find_constrained_delegation,
    find_kerberoastable,
    find_password_never_expires,
    find_password_not_required,
    find_rbcd,
    find_unconstrained_delegation,
)

SAMPLE = Path(__file__).parent.parent / "examples" / "sample_records.json"


def _records():
    return json.loads(SAMPLE.read_text())


def test_asrep_roastable_detected():
    findings = find_asrep_roastable(_records())
    accounts = [f.sam_account_name for f in findings]
    assert "legacy_app" in accounts
    # Disabled account with same flag should NOT be flagged
    assert "disabled_old" not in accounts


def test_kerberoastable_detected():
    findings = find_kerberoastable(_records())
    accounts = [f.sam_account_name for f in findings]
    assert "svc_sql" in accounts


def test_unconstrained_delegation_dc_marked_as_expected():
    findings = find_unconstrained_delegation(_records())
    dc_finding = next((f for f in findings if f.sam_account_name == "DC01$"), None)
    assert dc_finding is not None
    assert dc_finding.severity == "medium"
    assert "expected" in dc_finding.title


def test_constrained_delegation_detected():
    findings = find_constrained_delegation(_records())
    accounts = {f.sam_account_name: f for f in findings}
    assert "fileserver$" in accounts
    assert accounts["fileserver$"].severity == "medium"
    assert "iis_pool$" in accounts
    # Protocol-transition variant is more severe
    assert accounts["iis_pool$"].severity == "high"


def test_rbcd_detected():
    findings = find_rbcd(_records())
    assert any(f.sam_account_name == "rbcd_target$" for f in findings)


def test_password_not_required_critical():
    findings = find_password_not_required(_records())
    assert findings
    f = findings[0]
    assert f.sam_account_name == "broken_kiosk"
    assert f.severity == "critical"


def test_password_never_expires_admin():
    findings = find_password_never_expires(_records())
    accounts = [f.sam_account_name for f in findings]
    assert "old_admin" in accounts


def test_find_all_returns_sorted_by_severity():
    findings = find_all(_records())
    severities = [f.severity for f in findings]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert severities == sorted(severities, key=order.get)


def test_disabled_accounts_skipped_across_checks():
    findings = find_all(_records())
    # disabled_old has bad flags but is disabled — should appear in zero findings
    assert all(f.sam_account_name != "disabled_old" for f in findings)
