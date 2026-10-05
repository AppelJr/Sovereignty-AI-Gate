#!/usr/bin/env python3
"""
Heavy Judge + DevAssist420 Council preprocessor.

Fail-closed, SCAR-compatible review layer for multi-model routing.
Does not grant authority; it only scores and optionally rewrites output.
All decisions are intended to be recorded upstream via PolicyResolver / SCAR.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Model registry (declarative policy labels only — no execution authority)
# ---------------------------------------------------------------------------

MODEL_REGISTRY: dict[str, dict[str, str]] = {
    "SuperGrok-4.7": {"provider": "xai", "policy": "strict daily use"},
    "Grok-4.7": {"provider": "xai", "policy": "fallback"},
    "gpt-5.6-Luna-Terra-Sol": {"provider": "openai", "policy": "strict daily use"},
    "gpt-daybreak-red-latest": {"provider": "openai", "policy": "strict security"},
    "GPT-5.7-Codex-Cyber": {"provider": "openai", "policy": "security code syntax diff"},
    "Claude-sonnet-5.5": {"provider": "anthropic", "policy": "review and dashboards"},
    "Claude-Mythos-5.1": {"provider": "anthropic", "policy": "strict production live tasks"},
    "Claude-Fable-5.1": {"provider": "anthropic", "policy": "strict medical"},
    "Claude-Opus-5.5": {"provider": "anthropic", "policy": "medical escalation"},
    "GitHub Copilot": {"provider": "GitHub", "policy": "limited per session"},
    "DuckAI": {"provider": "DuckDuckGo", "policy": "strict privacy"},
    "DevAssist420+Sovereignty": {"provider": "local hybrid", "policy": "router + council"},
}


# ---------------------------------------------------------------------------
# Heavy Judge
# ---------------------------------------------------------------------------

class HeavyJudge:
    """
    Lightweight risk scorer and optional rewrite gate.

    This class does not hold production authority. It produces a verdict
    that an upstream PolicyResolver / SecurityBoundary can consume.
    Default action on high risk is "yank" (replace with safe text).
    """

    def __init__(
        self,
        model_name: str = "SuperGrok-5.7-hybrid",
        *,
        log_dir: Optional[Path] = None,
        voice_enabled: bool = False,
    ):
        self.model = model_name
        self.strictness = {
            "medical": 0.95,
            "education": 0.90,
            "general": 0.75,
        }
        self.log_dir = Path(log_dir) if log_dir else Path(".")
        self.voice_enabled = voice_enabled

    def _generate_verdict(
        self,
        text: str,
        context: str,
        risk_score: float = 0.0,
    ) -> dict[str, Any]:
        t = text.lower()
        keywords = {
            "medical": 50,
            "legal": 45,
            "safety": 50,
            "financial": 25,
        }
        score = 0.0
        for kw, weight in keywords.items():
            if kw in t:
                score += weight
        score += self.strictness.get(context.lower(), 0.75) * 10
        score = min(score, 100.0)

        if score >= 75:
            action = "yank"
        elif score >= 40:
            action = "rewrite"
        else:
            action = "pass"

        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "risk_score": score / 100.0,
            "action": action,
            "hash": hashlib.sha3_512(text.encode("utf-8")).hexdigest(),
            "signature": None,  # injected by PQC layer when available
            "context": context,
            "judge_model": self.model,
        }

    def _safe_replacement(self, original_output: str, context: str) -> str:
        return f"[Content replaced for safety — context={context}]"

    def review(
        self,
        original_output: str,
        context: str,
        risk_score: float = 0.0,
    ) -> dict[str, Any]:
        verdict = self._generate_verdict(original_output, context, risk_score)
        if verdict["action"] == "yank":
            final_output = self._safe_replacement(original_output, context)
        else:
            final_output = original_output

        return {
            "final_output": final_output,
            "verdict": verdict,
            "judge_model": self.model,
        }


# ---------------------------------------------------------------------------
# DevAssist420 preprocessor (local hybrid router label only)
# ---------------------------------------------------------------------------

def devassist420_preprocess(user_request: str, context: str) -> str:
    """
    Minimal local preprocessor. Does not call external providers.
    Returns a labeled council envelope for downstream review.
    """
    return f"[Council via DevAssist420 Hybrid | context={context}] {user_request}"


# ---------------------------------------------------------------------------
# Async side-effects (logging + optional Piper voice)
# ---------------------------------------------------------------------------

def _save_log_sync(verdict: dict, log_dir: Path) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_filename = log_dir / f"JudgeLog-{time.strftime('%Y-%m-%d')}.jsonl"
    with log_filename.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(verdict, sort_keys=True) + "\n")
    return log_filename


async def save_log_async(verdict: dict, log_dir: Path) -> Path:
    return await asyncio.to_thread(_save_log_sync, verdict, log_dir)


def _piper_voice_sync(final_text: str) -> None:
    """Best-effort offline TTS. Fails closed (no raise) if Piper is absent."""
    try:
        import subprocess
        subprocess.run(
            ["piper", "--model", "en_US-amy-low.onnx", "--sentence", final_text],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass


async def piper_voice_async(final_text: str) -> None:
    await asyncio.to_thread(_piper_voice_sync, final_text)


# ---------------------------------------------------------------------------
# Combined council + judge entrypoint
# ---------------------------------------------------------------------------

async def council_and_judge(
    user_request: str,
    context: str,
    *,
    log_dir: Optional[Path] = None,
    voice_enabled: bool = False,
) -> dict[str, Any]:
    """
    Preprocess → HeavyJudge review → optional background log/voice.

    Returns the review result. Does not itself call PolicyResolver;
    the caller should gate any side-effect with the authority plane.
    """
    primary_output = devassist420_preprocess(user_request, context)
    judge = HeavyJudge(log_dir=log_dir, voice_enabled=voice_enabled)
    result = judge.review(primary_output, context)

    tasks = [save_log_async(result["verdict"], Path(log_dir or "."))]
    if voice_enabled:
        tasks.append(piper_voice_async(result["final_output"]))
    await asyncio.gather(*tasks)

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    user_request = sys.argv[1] if len(sys.argv) > 1 else "<empty request>"
    context = sys.argv[2] if len(sys.argv) > 2 else "general"

    result = asyncio.run(council_and_judge(user_request, context))
    print("Final Output:", result["final_output"])
    print("Heavy Judge Verdict:", json.dumps(result["verdict"], indent=2))
