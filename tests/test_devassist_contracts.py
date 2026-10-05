import multiprocessing as mp
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from devassist_contracts import *  # noqa: F401,F403

D = "sha256:" + "a" * 64


def env(mode="GHOST", scope=("backend/x.py",)):
    return TaskEnvelope("t1", "derek", "edit", scope, mode, "2026-10-05T00:00:00Z", D)


def auth(**kw):
    base = dict(
        auth_id="a1",
        task_id="t1",
        allowed=True,
        expires_at=time.time() + 60,
        issued_by="gate",
    )
    base.update(kw)
    return GateAuthorization(**base)


def _worker(path, n):
    c = EvidenceChain(path)
    for i in range(n):
        c.append("TEST", "t1", D, {"i": i})


class ContractTests(unittest.TestCase):
    def test_bad_envelopes_rejected(self):
        for bad in (("/etc/passwd",), ("a/../b",), ()):
            with self.assertRaises(ContractError):
                env(scope=bad)
        with self.assertRaises(ContractError):
            env(mode="ONLINE")

    def test_no_auth_denies(self):
        self.assertEqual(decide_route(env(), None, "devassist_local").route, "deny")

    def test_expired_mismatched_denied_auth_deny(self):
        for a in (
            auth(expires_at=time.time() - 1),
            auth(task_id="other"),
            auth(allowed=False),
        ):
            self.assertEqual(decide_route(env(), a, "runtime_local").route, "deny")

    def test_local_route_allowed_with_auth(self):
        r = decide_route(env(), auth(), "devassist_local")
        self.assertEqual((r.route, r.gate_auth_id), ("devassist_local", "a1"))

    def test_ghost_never_external(self):
        r = decide_route(
            env("GHOST"),
            auth(),
            "runtime_external",
            frozenset({"api.x"}),
            "ok",
            "api.x",
        )
        self.assertEqual(r.route, "deny")

    def test_hybrid_needs_owner_approval(self):
        al = frozenset({"api.x"})
        self.assertEqual(
            decide_route(env("HYBRID"), auth(), "runtime_external", al, None, "api.x").route,
            "escalate",
        )
        self.assertEqual(
            decide_route(env("HYBRID"), auth(), "runtime_external", al, "own1", "api.x").route,
            "runtime_external",
        )

    def test_cloud_needs_allowlist(self):
        self.assertEqual(
            decide_route(env("CLOUD"), auth(), "runtime_external", frozenset(), None, "api.x").route,
            "deny",
        )
        self.assertEqual(
            decide_route(
                env("CLOUD"), auth(), "runtime_external", frozenset({"api.x"}), None, "api.x"
            ).route,
            "runtime_external",
        )

    def test_decision_cannot_exist_without_gate(self):
        with self.assertRaises(ContractError):
            RouteDecision("d", "t1", "devassist_local", "GHOST", "x")

    def test_receipt_rules(self):
        with self.assertRaises(ContractError):
            ExecutionReceipt("r", "t1", D, "devassist", "completed", "now")
        ExecutionReceipt("r", "t1", D, "devassist", "failed", "now")

    def test_lifecycle_chain_and_bindings(self):
        with tempfile.TemporaryDirectory() as d:
            chain = EvidenceChain(Path(d) / "scar.jsonl")
            e = env()
            rd = decide_route(e, auth(), "devassist_local")
            rc = ExecutionReceipt("r1", "t1", rd.digest(), "devassist420", "completed", "now", D)
            record_scar(chain, e)
            record_scar(chain, rd)
            s = record_scar(chain, rc)
            record_repmhl_handoff(chain, rc, s)
            self.assertTrue(chain.verify())
            other = ExecutionReceipt("r2", "t1", rd.digest(), "devassist420", "failed", "now")
            with self.assertRaises(ContractError):
                record_repmhl_handoff(chain, other, s)

    def test_meta_rejects_content(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ContractError):
                EvidenceChain(Path(d) / "x.jsonl").append("K", "t1", D, {"blob": "x" * 500})

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.jsonl"
            c = EvidenceChain(p)
            for i in range(3):
                c.append("K", "t1", D, {"i": i})
            p.write_text(p.read_text().replace('"i":1', '"i":9'))
            self.assertFalse(c.verify())

    def test_cross_process_chain_never_forks(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.jsonl"
            ps = [mp.Process(target=_worker, args=(str(p), 25)) for _ in range(4)]
            [x.start() for x in ps]
            [x.join() for x in ps]
            c = EvidenceChain(p)
            self.assertTrue(c.verify())
            self.assertEqual(len(p.read_text().splitlines()), 100)


if __name__ == "__main__":
    unittest.main()
