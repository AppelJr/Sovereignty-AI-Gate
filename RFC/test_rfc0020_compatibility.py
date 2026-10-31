"""
RFC-0020: Compatibility conformance tests.

Tests cross-RFC compatibility: that export bundles produced by one
instance can be imported by another, and that the ledger accumulates
all events correctly.
"""
import pytest
from sia import SovereignAuthority
from sia.delegation.models import DelegationToken
from sia.memory.models import MemoryRecord
from sia.imports.models import ImportBundle
from sia.utils.hashing import hash_object


def test_full_compatibility_pipeline():
    """
    Full pipeline test: init, register, delegate, memory, export, import,
    verify — all using two separate authority instances.
    """
    # --- Producer ---
    producer = SovereignAuthority(owner_id="user:alice")
    producer.initialize()

    producer.register_boundary("b-root", "model:gpt4", "creator", scope=["*"])

    token = DelegationToken(
        token_id="compat-tok-001",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["memory.read"],
    )
    producer.issue_delegation(token)

    mem = MemoryRecord(
        record_id="compat-mem-001",
        model_id="model:gpt4",
        content={"note": "compatibility test"},
    )
    producer.store_memory(mem)

    payload = {"test": "compat", "version": "0.1.0"}
    h = hash_object(payload)
    exported = producer.create_export("compat-exp-001", payload, h, "f" * 128)

    # Producer ledger must be intact
    producer.verify_ledger()

    # --- Consumer ---
    consumer = SovereignAuthority(owner_id="user:bob")
    consumer.initialize()

    inbound = ImportBundle(
        bundle_id=exported.bundle_id,
        created_by=exported.created_by,
        payload=exported.payload,
        payload_hash=exported.payload_hash,
        signature=exported.signature,
        created_at=exported.created_at,
    )
    consumer.load_import(inbound)
    consumer.verify_ledger()

    # Consumer ledger: init + import = 2
    assert len(consumer.ledger) == 2


def test_ledger_event_types_pipeline():
    sa = SovereignAuthority(owner_id="user:test")
    sa.initialize()
    sa.register_boundary("bx", "model:m", "creator", scope=[])

    token = DelegationToken(
        token_id="tx",
        grantor_id="user:test",
        grantee_id="model:m",
        scope=["*"],
    )
    sa.issue_delegation(token)
    sa.revoke_delegation("tx")

    event_types = [e.event_type for e in sa.ledger.all_entries()]
    assert "authority.init" in event_types
    assert "boundary.registered" in event_types
    assert "delegation.issued" in event_types
    assert "delegation.revoked" in event_types
