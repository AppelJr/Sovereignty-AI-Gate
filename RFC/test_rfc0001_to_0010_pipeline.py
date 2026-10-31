"""
RFC-0001 to RFC-0010: Pipeline conformance tests.

Tests the end-to-end flow: init → register boundary → issue delegation
→ store memory → export → import → verify.
"""
import pytest
from sia import SovereignAuthority
from sia.delegation.models import DelegationToken
from sia.memory.models import MemoryRecord
from sia.imports.models import ImportBundle
from sia.utils.hashing import hash_object


@pytest.fixture
def sa():
    authority = SovereignAuthority(owner_id="user:alice")
    authority.initialize()
    return authority


def test_pipeline_boundary_registration(sa):
    sa.register_boundary("b001", "model:gpt4", "creator", scope=["memory.read"])
    records = sa.registry.list_active()
    assert len(records) == 1
    assert records[0].boundary_id == "b001"


def test_pipeline_delegation(sa):
    token = DelegationToken(
        token_id="tok-001",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["memory.read"],
    )
    issued = sa.issue_delegation(token)
    assert issued.token_id == "tok-001"


def test_pipeline_memory_store_and_read(sa):
    record = MemoryRecord(
        record_id="mem-001",
        model_id="model:gpt4",
        content={"text": "hello"},
    )
    sa.store_memory(record)
    fetched = sa.read_memory("mem-001", "model:gpt4")
    assert fetched.record_id == "mem-001"


def test_pipeline_export(sa):
    payload = {"boundaries": [], "version": "0.1.0"}
    h = hash_object(payload)
    sig = "a" * 128
    bundle = sa.create_export("exp-001", payload, h, sig)
    assert bundle.bundle_id == "exp-001"


def test_pipeline_import(sa):
    payload = {"boundaries": [], "version": "0.1.0"}
    h = hash_object(payload)
    bundle = ImportBundle(
        bundle_id="imp-001",
        created_by="user:bob",
        payload=payload,
        payload_hash=h,
        signature="b" * 128,
        created_at="2026-01-01T00:00:00+00:00",
    )
    sa.load_import(bundle)


def test_pipeline_ledger_grows(sa):
    initial = len(sa.ledger)
    sa.register_boundary("b002", "model:claude", "reader", scope=["memory.read"])
    assert len(sa.ledger) == initial + 1


def test_pipeline_verify_ledger(sa):
    sa.register_boundary("b003", "model:grok", "delegate", scope=[])
    sa.verify_ledger()  # must not raise


def test_pipeline_policy_deny_by_default(sa):
    from sia.errors.exceptions import PolicyDeniedError
    with pytest.raises(PolicyDeniedError):
        sa.enforce_policy({"action": "some.action", "model_id": "model:x"})
