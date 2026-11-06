TULIP REASONING TRACE CONTRACT
Status: OWNER-ACCEPTED 2026-11-02 (Option B)
Owner: Appel420
Integrates with: LANE SPEC (Playground → Production), Decision Gate, Receipt Schema

PURPOSE
Make every gate decision auditable and correctable in real time.
Reasoning lives on-screen as an expandable trace.
Spoken / voice layer remains clean — no meta-narration of “I am now thinking…”.
The trace is part of the Tulip card itself, not a separate surface.

CARD STRUCTURE (every gated action)
1. Header
	•	Tulip ID (unique, generated per gate instance)
	•	Gate name / stage (Playground | Smoke | Real-Prod-Live | Production)
	•	Timestamp (ISO-8601, device local + UTC)
2. Reasoning Trace (expandable, collapsed by default)
	•	Trigger: exact user utterance or system event that opened this gate
	•	Steps: ordered list of the actual reasoning path taken
	•	Each step is a short factual statement (what was considered, what rule fired, what data was read)
	•	No speculative “I wonder if…” language
	•	Decision Point: the precise moment the system chose the proposed action / risk assessment
	•	Open Questions (if any): things the system flagged as unresolved before presenting Accept / Decline / Discuss
3. Decision Surface (Beat 1)
	•	Accept (green)
	•	Decline (red)
	•	Discuss (neutral)
	•	Risk / Reward / pro’s / con’s listed immediately above the buttons
	•	Embedded smoke-test plan that will run only after Accept
4. Receipt (Beat 2 — emitted on any choice)
Immutable line written into the thread:

RECEIPT | tulip_id=<id> | choice=<ACCEPT|DECLINE|DISCUSS> | ts=<ISO> | device_id=<id> | gate=<name>
5. Advance (Beat 3 — Key 1 only)
	•	ACCEPT advances the stage only
	•	Does not open the next door
	•	Next gate (Key 2) must present its own full card + fresh reasoning trace

HARD RULES
	1.	Reasoning trace is mandatory on every Tulip card. Missing trace = invalid card.
	2.	Trace content is generated before the card is shown; it is never post-hoc.
	3.	Spoken layer is forbidden from reading the trace aloud unless the user explicitly expands and requests it.
	4.	Discuss opens the current thread as the working surface; the locked reasoning + receipt stay visible at the top.
	5.	Any material change to the proposed action after Discuss requires a brand-new Tulip card with a new Tulip ID and new reasoning trace.
	6.	Sandbox is disallowed. All test execution stays inside the defined lanes (Local → Playground → Smoke → Real-Prod-Live → Production).

TWO-KEY MODEL (unchanged)
	•	Key 1 (this card’s Accept) = stage advance only
	•	Key 2 = separate downstream card that actually opens the door / performs the write / deploys

CREATOR ATTRIBUTION (5W1H + Merkle)
	•	Who: Appel420 / DevAssist420 routing key
	•	What: Reasoning Trace Card integrated into Tulip Decision Gate
	•	When: 2026-11-02
	•	Where: Local artifacts only (no cloud)
	•	Why: Make every gated decision correctable and auditable while keeping voice clean
	•	How: Expandable on-screen trace + immutable receipt + two-key advance

SMOKE-TEST PLAN (runs only after Accept of this contract)
	1.	Render a sample Tulip card containing a non-empty reasoning trace
	2.	Confirm spoken layer does not narrate the trace
	3.	Confirm receipt is emitted with all four required fields
	4.	Confirm Discuss keeps the original reasoning visible
	5.	Confirm Accept advances stage but does not open the next door

FILE TARGET
artifacts/tulip-reasoning-trace-contract.md

---
APPEND-ONLY SCAR / LEDGER HOOKS (production wiring)
Every Tulip card render and every choice MUST emit a ledger event via the existing AuditLedger (SHA3-512 hash chain, fsync on append):

- node = "TULIP"
- type on render = "CARD_RENDER"
- type on choice = "RECEIPT"
- data includes: tulip_id, gate, stage, choice (if any), trace_sha3_512, receipt_line, device_id

Receipt line is also written immutably into the conversation thread.
Retrieval: scan ledger for node=="TULIP" ordered by seq; verify chain continuity before any read-remember operation.
