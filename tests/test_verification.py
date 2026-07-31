from __future__ import annotations

import json
from pathlib import Path

from scripts.verify_junit import MAX_JUNIT_BYTES, verify_junit
from scripts.verify_readme_contract import HEADINGS, REQUIRED_EVIDENCE, verify_readme


def _write_junit(
    path: Path,
    *,
    passed: int = 1,
    failed: int = 0,
    errors: int = 0,
    skipped: int = 0,
) -> None:
    cases: list[str] = []
    cases.extend(f'<testcase name="pass-{index}" />' for index in range(passed))
    cases.extend(
        f'<testcase name="fail-{index}"><failure /></testcase>' for index in range(failed)
    )
    cases.extend(
        f'<testcase name="error-{index}"><error /></testcase>' for index in range(errors)
    )
    cases.extend(
        f'<testcase name="skip-{index}"><skipped /></testcase>' for index in range(skipped)
    )
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        '<testsuites><testsuite name="suite">'
        + "".join(cases)
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )


def _valid_readme() -> str:
    return "\n".join((*HEADINGS, *REQUIRED_EVIDENCE)) + "\n"


def test_positive_count_junit_creates_verified_atomic_receipt(tmp_path: Path) -> None:
    junit = tmp_path / "pytest.xml"
    output = tmp_path / "receipt.json"
    _write_junit(junit, passed=4, skipped=1)
    receipt = verify_junit(
        junit,
        output,
        pytest_exit_code=0,
        commit_sha="a" * 40,
        python_version="3.13.5",
    )
    assert receipt["conclusion"] == "VERIFIED"
    assert receipt["evidence_level"] == "TEST"
    assert receipt["tests"] == 5
    assert receipt["executed"] == 4
    assert len(receipt["junit_sha256"]) == 64
    assert json.loads(output.read_text(encoding="utf-8")) == receipt
    assert list(tmp_path.glob(".receipt.json.*.tmp")) == []


def test_zero_test_junit_cannot_establish_test_evidence(tmp_path: Path) -> None:
    junit = tmp_path / "pytest.xml"
    _write_junit(junit, passed=0)
    receipt = verify_junit(
        junit,
        tmp_path / "receipt.json",
        pytest_exit_code=0,
        commit_sha="b" * 40,
        python_version="3.12",
    )
    assert receipt["conclusion"] == "UNVERIFIED_ZERO_PROOF"
    assert receipt["executed"] == 0


def test_all_skipped_junit_cannot_establish_test_evidence(tmp_path: Path) -> None:
    junit = tmp_path / "pytest.xml"
    _write_junit(junit, passed=0, skipped=3)
    receipt = verify_junit(
        junit,
        tmp_path / "receipt.json",
        pytest_exit_code=0,
        commit_sha="c" * 40,
        python_version="3.11",
    )
    assert receipt["conclusion"] == "UNVERIFIED_ZERO_PROOF"


def test_failure_or_pytest_error_produces_failed_receipt(tmp_path: Path) -> None:
    junit = tmp_path / "pytest.xml"
    _write_junit(junit, passed=1, failed=1)
    receipt = verify_junit(
        junit,
        tmp_path / "receipt.json",
        pytest_exit_code=1,
        commit_sha="d" * 40,
        python_version="3.13",
    )
    assert receipt["conclusion"] == "FAILED"
    assert receipt["failures"] == 1


def test_entity_document_is_rejected(tmp_path: Path) -> None:
    junit = tmp_path / "pytest.xml"
    junit.write_text(
        '<!DOCTYPE testsuite [<!ENTITY x "expanded">]>'
        '<testsuite><testcase name="&x;" /></testsuite>',
        encoding="utf-8",
    )
    receipt = verify_junit(
        junit,
        tmp_path / "receipt.json",
        pytest_exit_code=0,
        commit_sha="e" * 40,
        python_version="3.13",
    )
    assert receipt["conclusion"] == "FAILED"
    assert "forbidden DTD" in receipt["reason"]


def test_non_utf8_document_is_rejected(tmp_path: Path) -> None:
    junit = tmp_path / "pytest.xml"
    junit.write_bytes("<testsuite />".encode("utf-16"))
    receipt = verify_junit(
        junit,
        tmp_path / "receipt.json",
        pytest_exit_code=0,
        commit_sha="f" * 40,
        python_version="3.13",
    )
    assert receipt["conclusion"] == "FAILED"
    assert "UTF-8" in receipt["reason"]


def test_oversized_document_is_rejected(tmp_path: Path) -> None:
    junit = tmp_path / "pytest.xml"
    junit.write_bytes(b" " * (MAX_JUNIT_BYTES + 1))
    receipt = verify_junit(
        junit,
        tmp_path / "receipt.json",
        pytest_exit_code=0,
        commit_sha="0" * 40,
        python_version="3.13",
    )
    assert receipt["conclusion"] == "FAILED"
    assert "exceeds" in receipt["reason"]


def test_readme_contract_accepts_ordered_portable_evidence(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(_valid_readme(), encoding="utf-8")
    assert verify_readme(readme) == ()


def test_readme_contract_rejects_wrong_order_and_local_paths(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        "\n".join((*reversed(HEADINGS), *REQUIRED_EVIDENCE, "/home/operator/repo")),
        encoding="utf-8",
    )
    errors = verify_readme(readme)
    assert "audience headings are out of order" in errors
    assert "README exposes a machine-local path" in errors


def test_headings_inside_code_fence_do_not_satisfy_contract(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        "\n".join(("```markdown", *HEADINGS, "```", *REQUIRED_EVIDENCE)),
        encoding="utf-8",
    )
    assert any(
        error.startswith("missing required audience headings")
        for error in verify_readme(readme)
    )
