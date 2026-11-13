"""Fail-closed owner-governed Playground state machine."""
from __future__ import annotations
import hashlib, json, sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Mapping

class PlaygroundError(RuntimeError): pass
class Decision(StrEnum):
    ACCEPT="ACCEPT"; DENY="DENY"; DISCUSS="DISCUSS"
class GateStatus(StrEnum):
    PROPOSED="PROPOSED"; ACCEPTED="ACCEPTED"; DENIED="DENIED"; DISCUSS="DISCUSS"
    PRETEST_BLOCKED="PRETEST_BLOCKED"; EXECUTION_AUTHORIZED="EXECUTION_AUTHORIZED"
    EXECUTED="EXECUTED"; PROMOTION_AUTHORIZED="PROMOTION_AUTHORIZED"
class ProviderOutcome(StrEnum):
    PASS="PASS"; REWRITE="REWRITE"; YANK="YANK"; JUDGE_DEAD="JUDGE_DEAD"

def _canonical(v: Any) -> bytes:
    return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def _digest(v: Any) -> str: return hashlib.sha3_512(_canonical(v)).hexdigest()
def _now() -> str: return datetime.now(timezone.utc).isoformat()

def resolve_provider_outcome(outcome: ProviderOutcome | str, *, grok_available: bool=True) -> dict[str,Any]:
    outcome=ProviderOutcome(outcome)
    if outcome is ProviderOutcome.JUDGE_DEAD:
        return {"status":"EMERGENCY_STATIC_POLICY_ONLY","allowed":False,"fallback":"versioned-static-policy","requires_scar":True}
    if outcome is ProviderOutcome.YANK: return {"status":"QUARANTINED","allowed":False,"fallback":None}
    if outcome is ProviderOutcome.REWRITE: return {"status":"REWORK_REQUIRED","allowed":False,"fallback":None}
    if not grok_available:
        return {"status":"DEGRADED_GROK_UNAVAILABLE","allowed":False,"primary":"GPT adversarial checks","backup":"Claude","judge_envelope_reduced":True,"requires_scar":True}
    return {"status":"PASS_PROPOSAL_ONLY","allowed":False,"fallback":None}

@dataclass(frozen=True)
class VerificationBinding:
    verified: bool
    owner_id: str
    device_id: str
    request_digest: str
    decision: str
    policy_version: str
    scope: str
    issued_at: str
    expires_at: str
    proof_ref: str
Verifier=Callable[[Mapping[str,Any]],VerificationBinding | Mapping[str,Any] | None]

class PlaygroundController:
    """Local SQLite event chain; injected verifier is the sole owner-auth boundary."""
    def __init__(self,database:str|Path,*,owner_id:str,policy_version:str,verifier:Verifier|None=None):
        if not owner_id or not policy_version: raise ValueError("owner_id and policy_version required")
        self.database=str(database); self.owner_id=owner_id; self.policy_version=policy_version; self.verifier=verifier
        with self._db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS requests(request_id TEXT PRIMARY KEY,payload TEXT NOT NULL,request_digest TEXT NOT NULL,status TEXT NOT NULL,pretest_status TEXT NOT NULL DEFAULT 'NOT_RUN',pretest_attempts INTEGER NOT NULL DEFAULT 0,execution_receipt TEXT,promotion_status TEXT NOT NULL DEFAULT 'BLOCKED',created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence(sequence INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT NOT NULL REFERENCES requests(request_id),event_type TEXT NOT NULL,payload TEXT NOT NULL,timestamp TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL UNIQUE);
            CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence BEGIN SELECT RAISE(ABORT,'append-only evidence'); END;
            CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence BEGIN SELECT RAISE(ABORT,'append-only evidence'); END;
            """)
    @contextmanager
    def _db(self):
        """Yield a SQLite connection and always close it.

        sqlite3.Connection.__exit__ commits or rolls back, but does NOT close
        the connection. Explicit finally cleanup is required (notably Python
        3.13 emits ResourceWarning for leaked connections).
        """
        db = sqlite3.connect(self.database)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
    @staticmethod
    def _validate(payload:Mapping[str,Any])->dict[str,Any]:
        p=dict(payload); keys=("what","why","who","when","where","how","risk","reward","pros","cons")
        missing=[k for k in keys if k not in p or p[k] in (None,"",[],{})]
        if missing: raise PlaygroundError("REQUEST_INCOMPLETE:"+",".join(missing))
        if not isinstance(p["pros"],list) or not isinstance(p["cons"],list): raise PlaygroundError("pros and cons must be lists")
        return p
    def _append(self,db,rid,event,payload):
        row=db.execute("SELECT event_hash FROM evidence ORDER BY sequence DESC LIMIT 1").fetchone()
        prev=row["event_hash"] if row else "0"*128; ts=_now()
        body={"request_id":rid,"event_type":event,"payload":dict(payload),"timestamp":ts,"previous_hash":prev}
        h=_digest(body)
        db.execute("INSERT INTO evidence(request_id,event_type,payload,timestamp,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",(rid,event,_canonical(dict(payload)).decode(),ts,prev,h))
        return {**body,"event_hash":h}
    def submit(self,request_id:str,payload:Mapping[str,Any])->dict[str,Any]:
        if not request_id: raise ValueError("request_id required")
        p=self._validate(payload); enc=_canonical(p).decode(); digest=_digest(p)
        with self._db() as db:
            if db.execute("SELECT 1 FROM requests WHERE request_id=?",(request_id,)).fetchone(): raise PlaygroundError("REQUEST_ID_ALREADY_EXISTS")
            db.execute("INSERT INTO requests(request_id,payload,request_digest,status,created_at) VALUES(?,?,?,?,?)",(request_id,enc,digest,GateStatus.PROPOSED.value,_now()))
            event=self._append(db,request_id,"REQUEST_SUBMITTED",{"request_digest":digest})
        return {"request_id":request_id,"request_digest":digest,"status":"PROPOSED","evidence":event}
    def _verify(self,row,decision,scope,proof):
        if self.verifier is None: raise PlaygroundError("OWNER_VERIFIER_UNAVAILABLE")
        challenge={"owner_id":self.owner_id,"request_id":row["request_id"],"request_digest":row["request_digest"],"decision":decision,"policy_version":self.policy_version,"scope":scope,"proof":dict(proof)}
        raw=self.verifier(challenge)
        if raw is None: raise PlaygroundError("OWNER_AUTHENTICATION_FAILED")
        b=raw if isinstance(raw,VerificationBinding) else VerificationBinding(**dict(raw))
        try: issued=datetime.fromisoformat(b.issued_at); expires=datetime.fromisoformat(b.expires_at); now=datetime.now(timezone.utc)
        except (TypeError,ValueError) as e: raise PlaygroundError("OWNER_PROOF_TIME_INVALID") from e
        if (not b.verified or b.owner_id!=self.owner_id or not b.device_id or b.request_digest!=row["request_digest"] or b.decision!=decision or b.policy_version!=self.policy_version or b.scope!=scope or not b.proof_ref or issued.tzinfo is None or expires.tzinfo is None or issued>now or expires<=now):
            raise PlaygroundError("OWNER_PROOF_BINDING_INVALID")
        return b
    def decide(self,request_id,decision,proof):
        d=Decision(decision)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE"); row=db.execute("SELECT * FROM requests WHERE request_id=?",(request_id,)).fetchone()
            if row is None: raise PlaygroundError("REQUEST_NOT_FOUND")
            if row["status"]!="PROPOSED": raise PlaygroundError("DECISION_ALREADY_FINAL")
            b=self._verify(row,d.value,"proposal-decision",proof)
            status={Decision.ACCEPT:"ACCEPTED",Decision.DENY:"DENIED",Decision.DISCUSS:"DISCUSS"}[d]
            db.execute("UPDATE requests SET status=? WHERE request_id=?",(status,request_id))
            ev=self._append(db,request_id,"OWNER_DECISION",{"decision":d.value,"owner_id":b.owner_id,"device_id":b.device_id,"policy_version":b.policy_version,"scope":b.scope,"proof_ref":b.proof_ref})
        return {"request_id":request_id,"status":status,"evidence":ev}
    def record_pretest(self,request_id,*,result,receipt):
        if result not in {"PASS","FAIL","BLOCKED","NOT_RUN","STALE","UNPROVEN"}: raise PlaygroundError("INVALID_PRETEST_STATUS")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE"); row=db.execute("SELECT * FROM requests WHERE request_id=?",(request_id,)).fetchone()
            if row is None: raise PlaygroundError("REQUEST_NOT_FOUND")
            if row["status"]!="ACCEPTED": raise PlaygroundError("PROPOSAL_NOT_ACCEPTED")
            attempts = row["pretest_attempts"] + (1 if result == "FAIL" else 0)
            if result == "PASS":
                status = "ACCEPTED"
            elif result == "FAIL" and attempts < 3:
                status = "ACCEPTED"
            elif result == "FAIL" and attempts >= 3:
                status = "DISCUSS"
            else:
                status = "PRETEST_BLOCKED"
            db.execute("UPDATE requests SET pretest_status=?,pretest_attempts=?,status=? WHERE request_id=?",(result,attempts,status,request_id))
            ev=self._append(db,request_id,"PRETEST_RESULT",{"result":result,"receipt":dict(receipt)})
        return {"request_id":request_id,"pretest_status":result,"attempts":attempts,"execution_eligible":result=="PASS","status":status,"evidence":ev}
    def authorize_execution(self,request_id,proof):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE"); row=db.execute("SELECT * FROM requests WHERE request_id=?",(request_id,)).fetchone()
            if row is None: raise PlaygroundError("REQUEST_NOT_FOUND")
            if row["status"]!="ACCEPTED" or row["pretest_status"]!="PASS": raise PlaygroundError("PRETEST_GATE_NOT_PASS")
            b=self._verify(row,"ACCEPT","execution",proof)
            db.execute("UPDATE requests SET status='EXECUTION_AUTHORIZED' WHERE request_id=?",(request_id,))
            ev=self._append(db,request_id,"EXECUTION_AUTHORIZED",{"owner_id":b.owner_id,"device_id":b.device_id,"policy_version":b.policy_version,"scope":b.scope,"proof_ref":b.proof_ref})
        return {"request_id":request_id,"status":"EXECUTION_AUTHORIZED","evidence":ev}
    def record_execution(self,request_id,*,receipt,success):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE"); row=db.execute("SELECT * FROM requests WHERE request_id=?",(request_id,)).fetchone()
            if row is None: raise PlaygroundError("REQUEST_NOT_FOUND")
            if row["status"]!="EXECUTION_AUTHORIZED": raise PlaygroundError("EXECUTION_NOT_AUTHORIZED")
            status="EXECUTED" if success else "PRETEST_BLOCKED"
            db.execute("UPDATE requests SET status=?,execution_receipt=? WHERE request_id=?",(status,_canonical(dict(receipt)).decode(),request_id))
            ev=self._append(db,request_id,"EXECUTION_RESULT",{"success":bool(success),"receipt":dict(receipt)})
        return {"request_id":request_id,"status":status,"evidence":ev}
    def authorize_promotion(self,request_id,proof):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE"); row=db.execute("SELECT * FROM requests WHERE request_id=?",(request_id,)).fetchone()
            if row is None: raise PlaygroundError("REQUEST_NOT_FOUND")
            if row["status"]!="EXECUTED": raise PlaygroundError("PROMOTION_REQUIRES_VERIFIED_EXECUTION")
            b=self._verify(row,"ACCEPT","promotion",proof)
            db.execute("UPDATE requests SET promotion_status='PROMOTION_AUTHORIZED' WHERE request_id=?",(request_id,))
            ev=self._append(db,request_id,"PROMOTION_AUTHORIZED",{"owner_id":b.owner_id,"device_id":b.device_id,"policy_version":b.policy_version,"scope":b.scope,"proof_ref":b.proof_ref})
        return {"request_id":request_id,"promotion_status":"PROMOTION_AUTHORIZED","evidence":ev}
    def verify_evidence(self):
        with self._db() as db: rows=db.execute("SELECT * FROM evidence ORDER BY sequence").fetchall()
        prev="0"*128
        for seq,row in enumerate(rows,1):
            payload=json.loads(row["payload"]); body={"request_id":row["request_id"],"event_type":row["event_type"],"payload":payload,"timestamp":row["timestamp"],"previous_hash":row["previous_hash"]}
            if row["sequence"]!=seq or row["previous_hash"]!=prev or _digest(body)!=row["event_hash"]: return {"valid":False,"failed_sequence":row["sequence"]}
            prev=row["event_hash"]
        return {"valid":True,"records":len(rows),"tip":prev}
    def snapshot(self,request_id):
        with self._db() as db: row=db.execute("SELECT * FROM requests WHERE request_id=?",(request_id,)).fetchone()
        if row is None: raise PlaygroundError("REQUEST_NOT_FOUND")
        return {"request_id":row["request_id"],"payload":json.loads(row["payload"]),"request_digest":row["request_digest"],"status":row["status"],"pretest_status":row["pretest_status"],"execution_receipt":json.loads(row["execution_receipt"]) if row["execution_receipt"] else None,"promotion_status":row["promotion_status"]}
