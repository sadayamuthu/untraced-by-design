"""
Replay recorded AgentDojo runs into anySQL through its public tracer API.

Each run becomes one session. Per message:
  user       -> AgentTracer.trace_user_task()   (agent_trace, step_type='user_task')
  assistant  -> GenericAdapter.log()           (llm_responses)
  tool call  -> AgentTracer.trace_tool_call()  (agent_tool_calls, input=args, output=result)

Ground truth (attack type, injection task, AgentDojo's `security` flag) is returned
separately as a labels DataFrame and never written into anySQL: detectors cannot see it.
The `injections` field (the injected text) is used only for the `delivered` label.

Data is untrusted input: run this with `python -I`.
"""

import json
import pathlib
import re

import pandas as pd

import anysql
from anysql.adapters.generic import GenericAdapter
from anysql.tracers.agent import AgentTracer

DOS_ATTACKS = {"dos", "captcha_dos", "felony_dos", "offensive_email_dos", "swearwords_dos"}


def session_key(d: dict) -> str:
    return "|".join(
        [
            d["pipeline_name"],
            d["suite_name"],
            d["user_task_id"],
            d["injection_task_id"] or "none",
            d["attack_type"] or "none",
        ]
    )


def load(runs_root: str, models: list[str], attacks: set[str] | None = None):
    """Return (db, labels). `attacks` filters attack types; 'none' = benign runs."""
    db = anysql.init(":memory:", enable_context_tracking=False)
    llm = GenericAdapter(db)
    labels = []
    for model in models:
        for f in sorted(pathlib.Path(runs_root, model).rglob("*.json")):
            d = json.loads(f.read_text())
            attack = d["attack_type"] or "none"
            if attacks is not None and attack not in attacks:
                continue
            sid = session_key(d)
            _replay(db, llm, sid, d)
            attacked = d["injection_task_id"] is not None
            # Label only: did any injected text reach a tool output the agent received?
            # Tool outputs re-wrap the injected text (YAML quoting, whitespace), so match the
            # longest line of each injection after collapsing whitespace and quotes.
            outputs = [_norm(_text(m.get("content"))) for m in d["messages"] if m["role"] == "tool"]
            keys = [_key(v) for v in (d.get("injections") or {}).values()]
            delivered = attacked and any(k and k in o for k in keys for o in outputs)
            labels.append(
                {
                    "session_id": sid,
                    "model": model,
                    "suite": d["suite_name"],
                    "user_task": d["user_task_id"],
                    "injection_task": d["injection_task_id"],
                    "attack": attack,
                    "attacked": attacked,
                    "delivered": delivered,
                    # AgentDojo sets security=True on benign runs too; only meaningful if attacked
                    "compromised": bool(attacked and d.get("security")),
                    "utility": bool(d.get("utility")),
                }
            )
    return db, pd.DataFrame(labels)


def _replay(db, llm, sid: str, d: dict) -> None:
    """Pair tool results with calls in message order: v1.2 runs have tool_call_id = null."""
    tracer = AgentTracer(db, session_id=sid)
    pending: list[dict] = []

    def flush_unanswered():
        for tc in pending:
            tracer.trace_tool_call(tc["function"], input=tc.get("args"), status="error",
                                   error_message="no tool result recorded")  # fmt: skip
        pending.clear()

    for m in d["messages"]:
        role = m["role"]
        if role == "user":
            tracer.trace_user_task(_text(m.get("content")))
        elif role == "assistant":
            flush_unanswered()
            llm.log(model=d["pipeline_name"], prompt="", content=_text(m.get("content")),
                    session_id=sid)  # fmt: skip
            pending.extend(m.get("tool_calls") or [])
        elif role == "tool":
            tc = pending.pop(0) if pending else (m.get("tool_call") or {"function": "unknown"})
            tracer.trace_tool_call(
                tc["function"],
                input=tc.get("args"),
                output=_text(m.get("content")),
                status="error" if m.get("error") else "success",
                error_message=m.get("error"),
            )
    flush_unanswered()


def _norm(s: str | None) -> str:
    s = (s or "").replace("\\n", " ")  # YAML-escaped newlines
    return re.sub(r"[\s'\"\\]+", " ", s).strip().lower()


def _key(injection: str) -> str:
    lines = [ln for ln in injection.splitlines() if ln.strip()]
    return _norm(max(lines, key=len)) if lines else ""


def _text(content) -> str | None:
    """AgentDojo content is a string, or (newer runs) a list of {type, content} parts."""
    if content is None or isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("content", "") if isinstance(p, dict) else str(p) for p in content)
    return str(content)
