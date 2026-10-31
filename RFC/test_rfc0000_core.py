"""
RFC-0000: Core authority protocol conformance tests.
"""
import pytest
from sia import SovereignAuthority
from sia.errors.exceptions import NotInitializedError


def test_core_owner_id():
    sa = SovereignAuthority(owner_id="user:alice")
    assert sa.owner_id == "user:alice"


def test_core_initialize_sets_flag():
    sa = SovereignAuthority(owner_id="user:alice")
    sa.initialize()
    assert sa._initialized is True


def test_core_double_initialize():
    sa = SovereignAuthority(owner_id="user:alice")
    sa.initialize()
    sa.initialize()
    assert len(sa.ledger) == 2


def test_core_not_initialized_raises():
    sa = SovereignAuthority(owner_id="user:alice")
    with pytest.raises(NotInitializedError):
        sa.register_boundary("b", "m", "creator", scope=[])


def test_core_version_in_init_event():
    sa = SovereignAuthority(owner_id="user:alice")
    sa.initialize()
    entry = sa.ledger.all_entries()[0]
    assert "version" in entry.payload
    assert entry.payload["version"] == "0.1.0"
