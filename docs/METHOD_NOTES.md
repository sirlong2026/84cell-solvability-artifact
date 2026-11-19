# Method notes

What was measured, how the records were selected, and which decisions a reader should disagree with
if they disagree with the paper. Everything here is stated in the manuscript; this file exists so the
artifact can be read without it.

## 1. Unit of observation

The unit is a **cell**: one exercise, one variant, one information level. A cell is not a student and
not a class. The measurement asks whether an exercise can be solved by an agent under a fixed budget,
not whether a student learned anything.

| Factor | Levels | Count |
|---|---|---|
| Exercise | t01 … t14 | 14 |
| Variant | `a` original, `b` paraphrase, `safe` patched | 3 |
| Information level | `L1` interface names and parameters shown, `L0` URL only | 2 |
| **Cells** | | **84** |

The harness also implements `L2` (source code supplied). It is not used here: with the source in
hand the exercise stops being a test of finding the vulnerability, which is a different measurement.

## 2. Fixed budget

Every cell is run with the same allowance: **5 rounds, 4096 tokens per round, 300 seconds per
round**, thinking disabled. Round count, token consumption, first-solve round, submitted flag and
claimed success are logged per run. Without a fixed budget the comparison between levels would
confound difficulty with spending.

## 3. Criterion

An item counts as **solved** only when the submitted output contains the expected flag. A run in
which the agent claims success but submits a wrong or absent flag is recorded as **hallucinated** and
never counted as a solve. The two observations are kept in separate fields
(`solved`, `claimed_solved`, `hallucinated`) precisely because collapsing them would inflate
solvability in the condition where the agent is least reliable.

The criterion is fixed in code before the runs and is not tuned per item. Its specificity is checked
by the `safe` variant: the same routes and parameters with the vulnerability patched, where the
correct answer is failure. A solve on a `safe` cell would mean the criterion fires when success is
impossible.

## 4. How a cell value was selected

The raw logs contain more than one record for some cells, so the selection rule has to be stated
exactly. The rules below are the ones `analysis/verify_all_numbers.py` applies; if you change them,
the numbers in the paper will not reproduce.

**Rule 1 — drop records with no observation.** A record whose `error` field begins with `INVALID`
means every API call in that run failed and no round completed (`no_successful_round`). It carries no
information about solvability and was rerun. Three kimi-k3.1-pro records (item t01) are of this kind.
Keeping them would have cost that model two cells and produced a spurious disagreement with the other
two models.

**Rule 2 — the primary model takes the last record per cell.** For deepseek-flash the value of a cell
is the last record in `runs_primary.jsonl`. The reruns were not random: 18 L1 cells received a second
or third record, and in 11 of them the superseded record carries a Docker failure (`docker cp`,
`docker run` rc=125, target container not ready, `docker rm` timeout). The last record is therefore
the first one that completed, not a favourable pick. `data/summary_counts.csv` reports the headline
counts both ways so the size of the correction is visible: 22 solved cells from last records, 17 from
first records.

**Rule 3 — each secondary model contributes one batch per level, and no batch overwrites another.**
qwen3.8-flash L1 comes from the batch of 27 September 2026 (42 cells). Its L0 comes from the same
batch for the 14 cells it reached, completed on 8 October 2026 for the 29 remaining cells; the one
cell present in both passes (t05-b) returned the same verdict, so the merge is a coverage completion,
not a selection. kimi-k3.1-pro comes from the batch of 19 November 2026 (42 + 42 cells).

This rule exists because an earlier draft of the analysis broke it. qwen3.8-flash also has a
repetition study in November 2026: 28 cells run ten times each, 280 records. Taking the last record
per cell across all qwen records mixed that study into the September batch and produced a 42-cell
snapshot of 47.6% that belonged to neither. The correct September figure is 45.2% (19/42), and the
scripts in `analysis/` now select by batch rather than by cell. The mixing is described here rather
than hidden because a reader who recomputes naively will hit the same trap.

**Rule 4 — comparison uses the intersection of cells.** Cross-model agreement is computed over cells
present for every model compared, which is all 42 per level.

## 5. The repeated-run studies are two different designs

They answer the same question in different ways and are not pooled.

| | qwen3.8-flash | deepseek-flash |
|---|---|---|
| Cells | 28 (L1) | 18 (L1) |
| Runs per cell | 10 | 2 or 3 |
| Why those cells | fixed subset, chosen in advance | cells that failed on infrastructure in the first pass |
| Cells with an identical verdict in every run | 16 (57.1%) | 8 (44.4%) |
| First-run rate on the subset | 71.4% (20/28) | 44.4% (8/18) |
| All-run rate on the subset | 70.0% (196/280) | 50.0% (22/44) |

The qwen design is a deliberate repetition study and is the one that supports a statement about
run-to-run noise: the aggregate rate moves 1.4 points under ten repetitions while 12 of 28 individual
verdicts flip at least once. The deepseek design is a repair of failed runs, so its subsets differ in
kind: its cells were selected by infrastructure failure, and the all-run mean moves upward from the
first-pass value, which is the direction a repair should move. Neither study estimates variance for
the full matrix.

## 6. Second host

All 84 cells were rerun on openEuler 22.03 LTS with the same model and budget. Headline rates are
unchanged (22 of 42 at L1, 2 of 42 at L0, 24 solved cells over the grid) and 80 of the 84 cells agree
individually. The four disagreements are single-cell flips.

## 7. What was excluded and why

- **GLM-5.3-Flash.** A batch was started on 19 November 2026 and abandoned. The endpoint timed out at
  180 s per call with four retries per round, so a cell cost about 800 s, and five of the first six
  records carried no observation. The records are not released and the model is not reported.
- **The wider corridor.** The 50 deployed images and 63 exploit writeups (13 duplicates) that the
  teacher uses as a manual reference are not part of the 84-cell measurement and are not released.
- **`L2`.** Implemented in the harness, not run.
- **Student data.** None was collected, so none appears here.

## 8. Known weaknesses of the design

These are the objections the authors would raise as reviewers, stated plainly so that they can be
checked rather than discovered.

1. **No human baseline.** 52.4% has no reference point. A sample of students attempting the same
   cells would convert the rate into a statement about discrimination; without it the paper can only
   say that the exercises are solvable, not how much of the variation a human would also produce.
2. **One run per cell in the primary matrix.** The cell value is an observed outcome, not an estimate
   of a success probability. No confidence interval is attached to any rate in the paper, and none
   should be read into one.
3. **Fourteen items.** Small enough that a single item moves a rate by 7 percentage points.
4. **Three models, one family of endpoints.** All three are served through OpenAI-compatible chat
   endpoints; a model with a different tool-use loop could behave differently.
5. **Budget sensitivity is untested.** 5 rounds and 4096 tokens are a teaching-department budget, not
   a frontier one. A larger budget would raise solvability and could change the level of the
   contrast, though not, on this item bank, its direction.
