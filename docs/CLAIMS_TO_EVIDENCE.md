# Claim to evidence

Every quantitative statement in the manuscript, the check that recomputes it, and the file it comes
from. Run `py analysis/verify_all_numbers.py` and match the ids.

## Abstract and Table 1

| Statement in the paper | Value | Check | Source |
|---|---|---|---|
| Fourteen exercises crossed with three variants and two levels, giving an 84-cell matrix | 84 | A1 | `data/matrix_84cell.csv` |
| All 28 patched safe cells returned zero | 0 of 28 | A2, A2b | `data/matrix_84cell.csv`, `data/summary_counts.csv` |
| Solvability fell from 52.4% at L1 | 22 of 42 | A3, A3b | `data/summary_counts.csv` |
| to 4.8% at L0 | 2 of 42 | A4, A4b | `data/summary_counts.csv` |
| 11 of the 12 L1-solvable exercises collapsed | 11 of 12 | A7, A7b | `data/matrix_84cell.csv` |
| Original variant solves at 85.7% at L1 | 12 of 14 | A5, A5b | `data/summary_counts.csv` |
| Paraphrase variant at 71.4% at L1 | 10 of 14 | A6, A6b | `data/summary_counts.csv` |
| Hallucination rises to 31.0% at L0 | 13 of 42 | A8 | `data/runs_primary.jsonl` via the matrix |
| Hallucination at 9.5% at L1 (the comparison) | 4 of 42 | A9 | `data/runs_primary.jsonl` via the matrix |
| At L0 the agent consumed 28,767 tokens on average | 28,767 | A10 | `data/matrix_84cell.csv` |
| and 4.8 rounds | 4.8 | A11 | `data/matrix_84cell.csv` |
| 24 of 84 cells solved over the whole grid | 24 | A12 | `data/matrix_84cell.csv` |

## Section 4.3, cross-model replication

| Statement | Value | Check | Source |
|---|---|---|---|
| qwen3.8-flash solved 45.2% of L1 cells | 19 of 42 | B1, B1b | `data/runs_agent.jsonl`, batch 2026-09-27 |
| and 4.8% of L0 cells | 2 of 42 | B2 | `data/runs_agent.jsonl`, batches 2026-09-27 and 2026-10-08 |
| kimi-k3.1-pro solved 54.8% of L1 cells | 23 of 42 | B3, B3b | `data/runs_agent.jsonl`, batch 2026-11-19 |
| and 7.1% of L0 cells | 3 of 42 | B4 | same |
| L1 solvability falls between 45% and 55% | 45.2 – 54.8 | B1b, B3b | derived |
| All three models agree on 35 of 42 L1 cells | 83.3% | B5, B5b | derived |
| Pairwise agreement 39/42, 38/42, 35/42 | 92.9%, 90.5%, 83.3% | B6, B7, B8 | derived |
| At L0 the three models agree on 41 of 42 cells | 97.6% | B9, B9b | derived |
| Four of the seven disagreements sit in the paraphrase variant | 4 of 7 | B10, B10b | derived |
| No disagreement involves a safe cell | 0 | B11 | derived |
| The smallest within-model gap is 40.4 points | 40.4 | B12 | derived |

## Section 4.3, repetition

| Statement | Value | Check | Source |
|---|---|---|---|
| A 28-cell L1 subset was run ten times per cell | 28 × 10 = 280 | C1, C1b | `data/runs_agent.jsonl` |
| The subset solved 196 of 280 runs | 70.0% | C2, C2b | same |
| against 20 of 28 cells in the first run alone | 71.4% | C3, C3b | same |
| a difference of 1.4 points | 1.4 | C4 | derived |
| Sixteen cells returned the same verdict in all ten runs | 57.1% | C5, C5b | same |
| Eighteen L1 cells received a second or third record | 18 | C6 | `data/runs_primary.jsonl` |
| The reruns total 44 records and 22 solves | 50.0% | C6b, C6c, C6d | same |
| Their first-pass rate was 8 of 18 | 44.4% | C6e | same |
| Eight held their verdict across every run | 44.4% | C7, C7b | same |
| Eleven reruns followed a logged infrastructure fault | 11 | C8 | same |
| and seven were repeated without a logged error | 7 | C8b | same |
| Five safe cells sit inside the repeated subset and returned zero in every run | 5 cells, 0 solves | C9, C9b | same |
| The 14 L1 safe cells returned zero in all three models | 0 | C10, C10b | `data/runs_agent.jsonl` |

## Section 4.3, environment

| Statement | Value | Check | Source |
|---|---|---|---|
| All 84 cells were rerun on a second host | 84 | D1 | `data/openeuler_runs.jsonl` |
| Headline rates unchanged, 22 at L1 and 2 at L0 | 24 of 84 | D1b, D1c, D1d | same |
| 80 of the 84 cells agree individually | 80 | D2 | same |
| Four disagreements | 4 | D3 | same |

## Integrity of the released analysis table

| Statement | Check |
|---|---|
| The matrix has one row per cell, 84 rows | E1 |
| The matrix can be rebuilt from the run records without a single difference | E2 |

## Statements the artifact cannot check

Three claims in the paper rest on material that is not in this repository and are not recomputed
here. They are listed so that a reviewer knows where the evidence stops.

1. **The 50 deployed images and 63 writeups (13 duplicates)** used as a manual reference for
   confirming that a solve followed the intended path. The corridor is not part of the 84-cell
   measurement.
2. **The classroom use described in Section 5**, including the mapping of items to course practicals
   and the competition context. This is teaching practice, not an experiment, and no data from it is
   analysed.
3. **No student data of any kind** was collected. This is a statement about the design, not a result
   that can be checked from files; the harness has no code path that accepts student input.
