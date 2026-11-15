# Untraced by Design: evaluation artefacts

Artefacts for the paper *Untraced by Design: Hunting Prompt-Injection Compromises in LLM
Agent Telemetry with SQL* (IEEE CSTA 2026).

The paper asks what a security team can find with SQL over recorded LLM agent sessions.
It replays 11,652 recorded [AgentDojo](https://github.com/ethz-spylab/agentdojo) runs into
[anySQL](https://github.com/sadayamuthu/anysql), runs six detection queries, and scores
them against AgentDojo's labels. The queries were written on one model (GPT-4o), frozen,
and then run unchanged on four held-out models.

## Contents

| Path | What |
|---|---|
| `load_agentdojo.py` | Replays recorded AgentDojo runs into anySQL through its public tracer API. One run is one session. Labels are kept outside anySQL, so queries cannot see them |
| `evaluate.py` | Runs the queries on the `dev` or `test` split and scores them at session level |
| `queries/*.sql` | The detection queries B0 and D1–D5, and the shared views in `_common.sql` |
| `queries/FROZEN.sha256` | SHA-256 hashes recorded before the first test run |
| `results/` | Raw outputs: per-query flags, labels, summaries by attack and by model, run logs |
| `RESULTS.md` | Results and findings in short form |

## Queries

| ID | Flags a session when | Uses wording? |
|---|---|---|
| B0 | a tool output contains "ignore (all) previous instructions" | yes |
| D1 | a tool output contains injection phrasing | yes |
| D2 | a state-changing call follows a D1 hit | yes |
| D3 | a state-changing call uses an identifier (email, IBAN, URL) absent from the user's request but present in an earlier tool output | no |
| D4 | a state-changing call's capability is not mentioned in the request | no |
| D5 | D3, and the source output also matched D1 | yes |

D3 is a sequencing heuristic: it shows that a value appeared in tool output before an
action used it, not that the output caused the action. See the paper for its false-positive
cost on benign sessions.

## Reproduce

Requires Python 3.10+ and git.

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt      # anySQL pinned to commit fe92f1a (version 0.2.0)

# AgentDojo recorded runs (MIT licence), at the commit used in the paper
git clone --filter=blob:none --sparse https://github.com/ethz-spylab/agentdojo.git data/agentdojo
git -C data/agentdojo checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60
git -C data/agentdojo sparse-checkout set runs/gpt-4o-2024-05-13 runs/claude-3-5-sonnet-20241022 \
    runs/meta-llama_Llama-3.3-70B-Instruct runs/gemini-1.5-pro-002 runs/gpt-4o-mini-2024-07-18

python -I evaluate.py dev
python -I evaluate.py test
```

`-I` runs Python in isolated mode, because the recorded runs are untrusted input. Outputs
are written to `results/`.

### Checking the freeze

```sh
shasum -a 256 -c queries/FROZEN.sha256
```

Every query and `evaluate.py` should report `OK`. `load_agentdojo.py` appears twice: the
first hash is the loader as frozen and is expected to fail; the second is the corrected
loader and should pass. The amendment note in the file explains the change: the first test
run loaded every AgentDojo v1.2.1 tool output as empty, because those runs record tool
results without call identifiers. The loader now pairs results with calls by message order.
The query files were not changed after the freeze.

## Data and licences

- Code and queries in this repository: Apache License 2.0 (see `LICENSE`).
- AgentDojo runs are not redistributed here; they are downloaded from the AgentDojo
  repository under its MIT licence. Files in `results/` contain session identifiers and
  evidence strings derived from those runs.
- anySQL: Apache License 2.0, https://github.com/sadayamuthu/anysql.

## Citation

K. Sadayamuthu, "Untraced by Design: Hunting Prompt-Injection Compromises in LLM Agent
Telemetry with SQL," in *Proc. IEEE Int. Conf. Cybersecurity Systems, Technologies and
Applications (CSTA)*, San Antonio, TX, USA, 2026.
