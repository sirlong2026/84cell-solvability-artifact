# Data dictionary

All files are UTF-8. JSON Lines means one JSON object per line, no wrapping array. CSV files have a
header row and are comma separated.

## `data/runs_agent.jsonl` — one row per agent run (617 rows)

The union of every batch reported in the paper: 154 deepseek-flash, 376 qwen3.8-flash, 87
kimi-k3.1-pro. qwen3.8-flash is larger because it carries both its matrix batches and its repetition
study.

| Field | Type | Meaning |
|---|---|---|
| `run_id` | str | Stable identifier, `model_item_variant_kN_level` plus a suffix for repeats, e.g. `deepseek_flash_t01_a_k1_L1fix`. |
| `ts` | str | Local start time, ISO 8601 without timezone. |
| `model_key` | str | Internal model key: `deepseek_flash`, `aliyun_qwen38_flash`, `kimi_k31_pro`. |
| `model_id` | str | Endpoint model name as sent in the request, e.g. `deepseek-flash`. |
| `task_id` | str | `t01` … `t14`. |
| `variant` | str | `a` original, `b` paraphrase, `safe` patched. |
| `cwe`, `kind` | str | Weakness class of the item and its short label. |
| `info_level` | str | `L1` interface names and parameters shown, `L0` URL only. |
| `k` | int | Replicate index within the batch. 1 for every run in the primary matrix. |
| `thinking` | str | `off` for every reported run. |
| `budget_rounds` | int | Round allowance, 5. |
| `rounds_used` | int | Rounds actually consumed. |
| `api_calls`, `api_errors` | int | Requests issued to the model, and how many failed. |
| `prompt_tokens`, `completion_tokens`, `total_tokens`, `reasoning_tokens` | int | Token accounting as reported by the endpoint. |
| `latency_total_s` | float | Time inside model calls. |
| `wall_s` | float | Time for the whole run including container work. |
| `solved` | 0/1 | **The criterion.** 1 only when the submitted output contains the expected flag. |
| `first_solve_round` | int or null | Round in which the flag was first seen. |
| `claimed_solved` | 0/1 | The agent asserted success. Independent of `solved`. |
| `claimed_flag` | str | The flag string the agent submitted, empty if none. |
| `claimed_correct` | 0/1 | `claimed_solved` and the claim matched the flag. |
| `hallucinated` | 0/1 | `claimed_solved` with a wrong or absent flag. |
| `exec_error_rounds` | int | Rounds in which the executed code failed. |
| `timeout_rounds` | int | Rounds that hit the 300 s ceiling. |
| `budget_exhausted` | 0/1 | The run used all five rounds without a solve. |
| `final_src` | str | The agent's last submitted program, as text. This is the audit trail for the verdict. |
| `evidence` | str | Harness-side output around the flag match, including the matched string. |
| `error` | str | Harness-level failure. Values beginning with `INVALID` mean no round completed and the record must be dropped (see `docs/METHOD_NOTES.md`, rule 1). Empty for a normal run. |

## `data/rounds_agent.jsonl` — one row per agent round (2,379 rows)

Joins to `runs_agent.jsonl` on `run_id`.

| Field | Type | Meaning |
|---|---|---|
| `run_id` | str | Parent run. |
| `round` | int | 1-based round index. |
| `latency_s` | float | Wall time for this round. |
| `prompt_tokens`, `completion_tokens` | int | Tokens for this round. |
| `src_len` | int | Length of the code extracted from the response, 0 if none. |
| `exec_kind` | str | What was executed, e.g. `no_code` when the model returned prose. |
| `rc` | int or null | Exit code of the executed program. |
| `timeout` | 0/1 | The round hit the time ceiling. |
| `out_snippet` | str | Truncated stdout/stderr. |
| `note` | str | Short reason the round ended, in Chinese in the original logs. |

## `data/runs_primary.jsonl` — the primary batch (114 rows)

Same schema as `runs_agent.jsonl`. deepseek-flash, batch of 26 September 2026: 84 cells plus 30
records that replaced runs lost to container faults. 68 rows at L1, 46 at L0.

## `data/matrix_84cell.csv` — the analysis table (84 rows)

One row per cell, holding the selected record. This is the table every headline number is computed
from.

| Column | Meaning |
|---|---|
| `task_id`, `variant`, `info_level` | Cell identity. |
| `cwe`, `kind` | Weakness class. |
| `run_id`, `ts` | The record the cell value was taken from. Follow this into `runs_primary.jsonl`. |
| `solved` | Cell value, 0/1. |
| `first_solve_round`, `rounds_used`, `total_tokens` | Cost of the selected record. |
| `claimed_solved`, `hallucinated` | Claim behaviour of the selected record. |
| `exec_error_rounds`, `timeout_rounds` | Round-level failures. |
| `attempts_in_cell` | How many records exist for this cell in `runs_primary.jsonl`. Values above 1 mark a cell that was rerun. |

## `data/summary_counts.csv` — headline counts under both selection rules

| Column | Meaning |
|---|---|
| `indicator` | Quantity. |
| `value_last_run_per_cell` | The value used in the paper. |
| `value_first_run_per_cell` | The same quantity computed from the first record of each cell, so a reader can see how much the infrastructure reruns moved each number. |
| `note` | Definition, in Chinese in the original export. |

## `data/openeuler_runs.jsonl` — second-host replication (84 rows)

Same schema as `runs_agent.jsonl`. deepseek-flash on openEuler 22.03 LTS, one record per cell, no
reruns. This is the batch behind the environment replication in Section 4.3.

## What is not in the data

No student identifiers, no course enrolment, no grades, no timestamps of teaching activity. The
harness has no code path that reads student input. Network addresses in the run logs are loopback and
Docker-internal (`target:8080`, `172.19.0.0/16`) plus the link-local metadata address used as a
server-side request forgery payload; no address outside the test host appears.
