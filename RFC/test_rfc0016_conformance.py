"""
RFC-0016: Conformance harness tests.

Tests the ConformanceHarness registration, execution, evidence
recording, and summary reporting.
"""
import pytest
from sia.conformance.harness import ConformanceHarness
from sia.conformance.evidence import EvidenceRecord
from sia.errors.exceptions import ConformanceAssertionError


def test_harness_empty_run():
    h = ConformanceHarness()
    results = h.run_all()
    assert results == []


def test_harness_passing_assertion():
    h = ConformanceHarness()

    @h.register("RFC-0016", "A001")
    def check_pass():
        return {"detail": "ok"}

    results = h.run_all()
    assert len(results) == 1
    assert results[0].result == "pass"
    assert results[0].rfc == "RFC-0016"


def test_harness_failing_assertion():
    h = ConformanceHarness()

    @h.register("RFC-0016", "A002")
    def check_fail():
        raise ConformanceAssertionError("deliberate failure")

    results = h.run_all()
    assert len(results) == 1
    assert results[0].result == "fail"
    assert "deliberate failure" in results[0].details["error"]


def test_harness_summary():
    h = ConformanceHarness()

    @h.register("RFC-0016", "A003")
    def p():
        pass

    @h.register("RFC-0016", "A004")
    def f():
        raise ConformanceAssertionError("fail")

    h.run_all()
    summary = h.summary()
    assert summary["pass"] == 1
    assert summary["fail"] == 1


def test_harness_run_rfc_filter():
    h = ConformanceHarness()
    h.add("RFC-0014", "M001", lambda: None)
    h.add("RFC-0015", "D001", lambda: None)

    results = h.run_rfc("RFC-0014")
    assert len(results) == 1
    assert results[0].rfc == "RFC-0014"


def test_harness_evidence_has_id():
    h = ConformanceHarness()

    @h.register("RFC-0016", "A005")
    def ok():
        pass

    results = h.run_all()
    assert results[0].evidence_id  # non-empty


def test_harness_passed_property():
    h = ConformanceHarness()
    h.add("RFC-0016", "A006", lambda: None)
    h.run_all()
    assert h.passed() is True


def test_harness_passed_false_on_failure():
    h = ConformanceHarness()
    h.add(
        "RFC-0016", "A007",
        lambda: (_ for _ in ()).throw(ConformanceAssertionError("x"))
    )
    h.run_all()
    assert h.passed() is False
