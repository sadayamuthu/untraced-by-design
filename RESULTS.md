# Evaluation: SQL detection of prompt-injection attacks on AgentDojo runs

Recorded AgentDojo runs (MIT; commit `089ed46`) replayed into anySQL (`fe92f1a`, branch
`feat/cross-layer-provenance`) through its public tracer API. One run = one session.
Session-level scoring against AgentDojo's labels. DoS attacks excluded (different goal).

- **dev** (queries written and revised here): GPT-4o-2024-05-13, 10 attack types + benign. 6,414 sessions.
- **test** (held out, queries frozen first, see `queries/FROZEN.sha256`): Claude 3.5 Sonnet (Oct),
  Gemini 1.5 Pro 002, GPT-4o-mini: `important_instructions` + benign; Llama 3.3 70B: `important_instructions`, `ignore_previous`, `direct` (the attacks in its recorded runs) + benign.
  5,238 sessions: 504 benign, 4,082 resisted attacks, 652 successful attacks.

Labels: *delivered* = injected text reached a tool output (label only, from AgentDojo's
`injections` field; detectors never see it). *Compromised* = attacked and AgentDojo `security=True`.

## Queries (`queries/`)

| ID | What it flags | Layers | Text signature? | OWASP LLM 2025 / ATLAS* |
|---|---|---|---|---|
| B0 | "ignore (all) previous instructions" in a tool output | tool output | yes (classic) | LLM01 / AML.T0051.001 |
| D1 | Generic injection phrasing in a tool output (override, addressing the model, task hijack, tool direction) | tool output | yes | LLM01 / AML.T0051.001 |
| D2 | A state-changing call after a D1 hit | tool output → later action | yes | LLM01, LLM06 |
| D3 | A state-changing call whose argument (email, IBAN, URL) is absent from the user's request but present in an earlier tool output | user task × tool outputs × action args | **no** | LLM01, LLM06, LLM02 / AML.T0057 |
| D4 | A state-changing call whose capability the user's request never mentions | user task × actions | **no** | LLM06 |
| D5 | D3 where the source output also matched D1 | user task × injected output × action | yes | LLM01, LLM06 |

\*ATLAS IDs to verify against the current ATLAS matrix before submission.

## Held-out test results (95% Wilson CIs in `results/test_summary.csv`)

| Query | Successful attacks caught | False alarms: resisted attacks | False alarms: benign | Precision among attacked |
|---|---|---|---|---|
| B0 | 0.000 | 0.000 | 0.000 | — |
| D1 | **0.939** | 0.585 | 0.000 | 0.204 |
| D2 | 0.913 | 0.307 | 0.000 | 0.322 |
| D3 | 0.771 | 0.131 | 0.121 | 0.486 |
| D4 | 0.408 | 0.042 | 0.028 | 0.610 |
| D5 | 0.707 | 0.086 | 0.000 | 0.567 |
| D3 ∨ D4 | 0.877 | 0.152 | 0.147 | 0.480 |
| D3 ∧ D4 | 0.302 | **0.020** | 0.002 | **0.704** |

Successful attacks caught, by attack type (test):

| Attack | D1 (signature) | D3 (provenance, no signature) | D3 ∨ D4 |
|---|---|---|---|
| important_instructions | 0.990 | 0.758 | 0.871 |
| ignore_previous | 0.991 | 0.789 | 0.886 |
| **direct** ("TODO: …", no injection phrasing) | **0.000** | **0.912** | 0.941 |

## Findings

1. **Signatures find attempts, not compromises.** D1 catches 94% of successful attacks but
   fires on 59% of attacks the model resisted. Precision among attacked sessions is 0.20.
   It cannot tell an analyst which sessions need a response.
2. **Signatures miss plain-language injections.** On `direct` (an injected "TODO:" line) D1
   catches 0%. The classic phrase (B0) catches 0% on test: one typo ("iunstructions") or
   rewording defeats it.
3. **Provenance needs no wording.** D3 joins the user's request, earlier tool outputs and
   action arguments. It catches 77% of successful attacks overall and 91% of `direct` attacks,
   with 13% false alarms on resisted attacks.
4. **Provenance has a real false-positive cost.** D3 flags 12% of benign sessions:
   legitimate flows ("pay the bill in this file") also act on identifiers read from tool output.
   Combining layers trades recall for precision: D3 ∧ D4 reaches 0.70 precision with 2% false
   alarms on resisted attacks and 0.2% on benign, at 30% recall.
5. **The cross-layer join needs ordered, shared sessions.** All of D2–D5 depend on the
   per-session step sequence added to anySQL for this paper (`../README.md`, provenance finding).

## Caveats

- Claude 3.5 Sonnet had only 7 successful attacks; its per-model rates are very uncertain.
- Benign sets are small (124 dev, 504 test sessions); a 0.000 benign FPR has CI up to ~0.01–0.03.
- D1 patterns come from published injection phrasing, and were checked on dev data that uses
  AgentDojo's templates. D1's recall on unseen phrasing is likely lower than reported; `direct` shows how far.
- D4's per-tool keyword lists were written from the AgentDojo tool names; a new tool needs a new entry.
- Detection is after the fact; queries run on recorded traces.
- Recorded runs, not live agents: results describe these models' 2024–2025 behaviour.
- Loader bug found on the first test run (v1.2 runs have `tool_call_id = null`, so tool outputs
  were loaded empty). Fixed by pairing in message order; queries unchanged. Logged in `FROZEN.sha256`.

## Reproduce

```bash
cd eval
git clone --filter=blob:none --sparse https://github.com/ethz-spylab/agentdojo.git data/agentdojo
git -C data/agentdojo checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60
git -C data/agentdojo sparse-checkout set runs/gpt-4o-2024-05-13 runs/claude-3-5-sonnet-20241022 \
    runs/meta-llama_Llama-3.3-70B-Instruct runs/gemini-1.5-pro-002 runs/gpt-4o-mini-2024-07-18
# anySQL at fe92f1a installed in the interpreter (pip install -e ../../openastra/anySQL)
python -I evaluate.py dev
python -I evaluate.py test
```
