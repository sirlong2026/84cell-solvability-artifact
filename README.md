# Reproduction artifact: an 84-cell diagnosis of exercise solvability under AI assistance

This repository holds the data, the harness and the analysis scripts behind the manuscript
*Diagnosing Exercise Validity under AI Assistance: An 84-Cell Study in Vocational Cybersecurity
Education*. Everything the paper reports can be recomputed from the files here, and every one of
those recomputations is checked by a single command that needs no Docker, no API key and no network
access.

The object of measurement is the **exercise**, not the student. Fourteen containerised
capture-the-flag exercises are crossed with three variants (original, paraphrase, patched safe) and
two information levels (interface names shown, L1; URL only, L0), which gives 84 cells. An agent
attempts every cell under a fixed budget, and the outcome is recorded per cell together with the
per-round transcript that produced it.

## Quick check

```
py analysis/verify_all_numbers.py         # Windows launcher
python3 analysis/verify_all_numbers.py    # macOS, Linux
```

The script recomputes every reported quantity from `data/` and compares it with the value printed in
the paper, one line per quantity:

```
id    in paper  quantity                                     paper    recomputed  status
A3    Table 1   L1 solvability, solved cells (of 42)         22       22          PASS
A4b   Table 1   L0 solvability, percent                      4.8      4.8         PASS
...
65 checks, 0 failed
```

Exit code is 0 only when all 65 checks pass. `docs/CLAIMS_TO_EVIDENCE.md` maps each sentence of the
results section to the check id that verifies it.

## What is where

| Path | Contents |
|---|---|
| `data/runs_agent.jsonl` | One record per agent run: model, item, variant, level, budget use, outcome, submitted flag, error. 617 records, three models. |
| `data/rounds_agent.jsonl` | One record per agent round: what was executed, exit code, output excerpt, why the round ended. 2,379 records. |
| `data/runs_primary.jsonl` | The primary model's batch (deepseek-flash, 26 September 2026), including the reruns issued after container faults. 114 records. |
| `data/matrix_84cell.csv` | The 84-row analysis table: one row per cell with the selected record, its outcome, cost and hallucination flag. |
| `data/summary_counts.csv` | The headline counts, given both for the last and the first record per cell so that the effect of the reruns is visible. |
| `data/openeuler_runs.jsonl` | The full 84-cell replication on a second host (openEuler 22.03 LTS). 84 records. |
| `tasks/` | The 14 exercise definitions: route, parameter aliases, functional checks, flag, and the Flask implementation used to serve the target. |
| `harness/` | The evaluation harness: agent loop, matrix driver, container driver, flag judge, container image. |
| `analysis/` | `verify_all_numbers.py` (all reported numbers), `prepare_release.py` (how `data/` was cut from the raw lab logs). |
| `docs/` | Method notes, item bank, claim-to-evidence map, data dictionary, checksums. |

## The measurement in one table

Read from `data/matrix_84cell.csv`, primary model, one selected record per cell:

| Indicator | Value | Check |
|---|---|---|
| Cells completed | 84 of 84 | A1 |
| Safe true-negative cells solved | 0 of 28 | A2 |
| L1 solvability | 52.4% (22/42) | A3 |
| L0 solvability | 4.8% (2/42) | A4 |
| L1-solvable items that collapse at L0 | 11 of 12 | A7 |
| Hallucination rate | 9.5% at L1, 31.0% at L0 | A8, A9 |
| Cross-model L1 range | 45.2% – 54.8% | B1, B3 |
| Cell-level agreement, three models | 83.3% at L1, 97.6% at L0 | B5, B9 |
| Repetition, 28 cells × 10 runs | 70.0% all-run vs 71.4% first-run | C2, C3 |
| Second host | 24 of 84 cells solved, 80 of 84 agree cell by cell | D1, D2 |

## Running the harness again

`REPRODUCE.md` gives the commands. In short, each cell needs Docker and an API key for the model
under test; the batch in the paper took about 90 seconds per cell on a 4-core host. Reviewers who
only want to audit the numbers do not need to run anything beyond the quick check.

## Two things a reader should know before reading the data

**The flags are in the data.** The exercises are self-built training targets whose flags exist only
inside this experiment; they are published so that a reader can confirm that a cell recorded as
solved really submitted the expected string. No flag protects anything outside the artifact.

**A fourth model is absent on purpose.** A batch on GLM-5.3-Flash was started on 19 November 2026
and abandoned: the endpoint timed out at 180 s per call, four retries per round, so a single cell
cost about 800 s and five of the first six records carried no observation. Those records are not
released and the model is not reported. The three models that are reported each cover the full
matrix.

## Scope

The artifact supports claims about the solvability of these 14 exercises by these three models under
this budget. It does not support claims about student learning, about teacher behaviour, or about the
effect of any intervention, and no student data of any kind was collected, stored or processed. The
absolute level of solvability has no human baseline; `docs/METHOD_NOTES.md` says what would be needed
to supply one.

## License and citation

Code is released under the MIT license, data and task definitions under CC BY 4.0. See `LICENSE`.
`CITATION.cff` carries the metadata for this artifact; the author block is intentionally neutral
while the manuscript is under double-blind review.
