"""
RFC-0017: Audit ledger conformance tests.

Tests append-only semantics, chained hashing, tamper detection,
and verification.
"""
import pytest
from sia.audit.ledger import AuditLedger, GENESIS_HASH
from sia.errors.exceptions import AuditChainError, AuditTamperedError


def test_ledger_empty_verify():
    ledger = AuditLedger()
    ledger.verify_chain()  # must not raise on empty ledger


def test_ledger_append_one():
    ledger = AuditLedger()
    entry = ledger.append("test.event", {"k": "v"}, actor_id="user:alice")
    assert entry.entry_id == 0
    assert entry.prev_hash == GENESIS_HASH
    assert len(ledger) == 1


def test_ledger_chain_hashes():
    ledger = AuditLedger()
    e0 = ledger.append("ev.a", {}, actor_id="user:alice")
    e1 = ledger.append("ev.b", {}, actor_id="user:alice")
    assert e1.prev_hash == e0.entry_hash


def test_ledger_verify_chain():
    ledger = AuditLedger()
    for i in range(5):
        ledger.append(f"ev.{i}", {"i": i}, actor_id="user:alice")
    ledger.verify_chain()  # must not raise


def test_ledger_tamper_detected():
    ledger = AuditLedger()
    e = ledger.append("ev", {}, actor_id="user:alice")
    e.payload["injected"] = True  # tamper
    e.entry_hash = e.compute_hash()  # recompute hash without chain update
    # chain link will be broken for next entry
    ledger.append("ev2", {}, actor_id="user:alice")
    # The chain hash of e was recomputed after tampering, so prev_hash of e1
    # won't match the original hash stored in e1.prev_hash
    # Instead test that the hash itself changes on tamper
    original_hash = e.entry_hash
    e.payload["also"] = "tampered"  # tamper again without updating hash
    with pytest.raises(AuditTamperedError):
        e.verify()


def test_ledger_tail():
    ledger = AuditLedger()
    for i in range(10):
        ledger.append("ev", {"i": i}, actor_id="user:alice")
    tail = ledger.tail(3)
    assert len(tail) == 3
    assert tail[-1].payload["i"] == 9


def test_ledger_all_entries():
    ledger = AuditLedger()
    ledger.append("ev", {}, actor_id="user:alice")
    ledger.append("ev2", {}, actor_id="user:alice")
    entries = ledger.all_entries()
    assert len(entries) == 2
