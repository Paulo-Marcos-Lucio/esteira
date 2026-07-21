from __future__ import annotations

from pathlib import Path

from esteira.checks.engine import scan
from esteira.core.models import Severity


def _ids(root: Path) -> set[str]:
    return {f.check_id for f in scan(root).findings}


def test_vuln_workflow_triggers_all_families(vuln_repo: Path) -> None:
    ids = _ids(vuln_repo)
    expected = {
        "script-injection",
        "pull-request-target-checkout",
        "unpinned-action-thirdparty",
        "unpinned-action-firstparty",
        "broad-permissions",
        "secret-in-run",
        "curl-pipe-shell",
        "self-hosted-runner",
        "dangerous-trigger",
    }
    assert expected <= ids


def test_safe_workflow_is_clean(safe_repo: Path) -> None:
    assert scan(safe_repo).findings == []


def test_script_injection_has_line_number(vuln_repo: Path) -> None:
    findings = [f for f in scan(vuln_repo).findings if f.check_id == "script-injection"]
    assert findings
    assert all(f.line > 0 for f in findings)


def test_thirdparty_is_high_firstparty_is_low(vuln_repo: Path) -> None:
    findings = scan(vuln_repo).findings
    third = next(f for f in findings if f.check_id == "unpinned-action-thirdparty")
    first = next(f for f in findings if f.check_id == "unpinned-action-firstparty")
    assert third.severity is Severity.HIGH
    assert first.severity is Severity.LOW


def test_only_and_skip_filters(vuln_repo: Path) -> None:
    only = {f.check_id for f in scan(vuln_repo, only=["curl-pipe-shell"]).findings}
    assert only == {"curl-pipe-shell"}
    skipped = {f.check_id for f in scan(vuln_repo, skip=["script-injection"]).findings}
    assert "script-injection" not in skipped


def test_missing_permissions_detected(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows" / "np.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n", encoding="utf-8"
    )
    ids = {f.check_id for f in scan(tmp_path).findings}
    assert "missing-permissions" in ids
