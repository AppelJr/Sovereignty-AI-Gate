"""
RFC-0013: Root boundary conformance tests.

The root boundary is the first boundary registered by the owner.
It defines the trust anchor for all subsequent delegations.
"""
import pytest
from sia import SovereignAuthority
from sia.errors.exceptions import RegistryDuplicateError


@pytest.fixture
def sa():
    authority = SovereignAuthority(owner_id="user:alice")
    authority.initialize()
    return authority


def test_root_boundary_registered(sa):
    sa.register_boundary("root-b001", "model:root", "creator", scope=["*"])
    record = sa.registry.get("root-b001")
    assert record.boundary_id == "root-b001"
    assert record.creator_id == "user:alice"
    assert record.boundary_type == "creator"


def test_root_boundary_duplicate_raises(sa):
    sa.register_boundary("root-b001", "model:root", "creator", scope=["*"])
    with pytest.raises(RegistryDuplicateError):
        sa.register_boundary("root-b001", "model:root2", "creator", scope=[])


def test_root_boundary_creator_is_owner(sa):
    sa.register_boundary("root-b002", "model:root", "creator", scope=["*"])
    record = sa.registry.get("root-b002")
    assert record.creator_id == sa.owner_id


def test_root_boundary_in_active_list(sa):
    sa.register_boundary("root-b003", "model:x", "creator", scope=[])
    active = sa.registry.list_active()
    ids = [r.boundary_id for r in active]
    assert "root-b003" in ids


def test_root_boundary_deactivate(sa):
    sa.register_boundary("root-b004", "model:y", "creator", scope=[])
    sa.registry.deactivate("root-b004")
    record = sa.registry.get("root-b004")
    assert record.active is False
    active = sa.registry.list_active()
    ids = [r.boundary_id for r in active]
    assert "root-b004" not in ids
