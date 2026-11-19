# Reproducing the measurement

Three levels of reproduction, in increasing cost. The first is enough to audit the paper.

Commands are written with the Windows launcher `py`; on macOS or Linux use `python3` and bash syntax.

## 1. Audit the reported numbers (no Docker, no key, no network)

```
py analysis/verify_all_numbers.py
```

Python 3.8 or later, standard library only. The script reads the four files in `data/`, applies the
selection rules in `docs/METHOD_NOTES.md`, and prints one line per reported quantity with the value
from the paper, the value it recomputed, and PASS or FAIL. It exits non-zero if anything disagrees,
so it can be used as a gate:

```
py analysis/verify_all_numbers.py && echo "paper and data agree"
```

Two useful variants while reading:

```
py analysis/verify_all_numbers.py | grep FAIL      # only disagreements
py analysis/verify_all_numbers.py | grep "Table 1" # only the main table
```

`data/matrix_84cell.csv` is the cell-level view; every row names the `run_id` it was taken from, so a
single cell can be traced back into `runs_agent.jsonl` (outcome, budget use, submitted flag) and from
there into `rounds_agent.jsonl` (what the agent executed in each round and what came back).

## 2. Rebuild the analysis table from the run records

Check `E2`, which runs with everything else, does exactly this: it recomputes all 84 cell values from
`data/runs_primary.jsonl` and compares them with the shipped `matrix_84cell.csv`. A mismatch means
the analysis table and the run records have drifted apart. To watch the rebuild on its own:

```
py analysis/verify_all_numbers.py | grep -E "^(E1|E2)"
```

## 3. Rerun the agent (Docker, an API key, about 90 s per cell)

Requirements: Python 3.8+, a working Docker daemon, and an API key for the model under test. The
harness talks to the model through an OpenAI-compatible chat endpoint; the endpoint and the
environment variable that carries its key are declared in the `MODELS` table at the top of
`harness/bench.py`.

```bash
cd harness

# build the target image once
docker build -f Dockerfile.agent -t dsa-agent:latest .

# credentials, never written to disk
export DEEPSEEK_API_KEY=...

# one cell, as a smoke test
python bench.py --task t01 --variant a --info-level L1 --k 1

# one level of the matrix (42 cells)
python run_matrix.py --level L1 --tag myL1 --k 1

# the whole matrix
python run_matrix.py --level L1 --tag myL1 --k 1
python run_matrix.py --level L0 --tag myL0 --k 1
```

`run_matrix.py` skips any (model, level, item, variant, k) combination already present in
`runs_agent.jsonl`, so an interrupted batch can be restarted with the same command. Output goes to
`runs_agent.jsonl` and `rounds_agent.jsonl` in the working directory.

Fixed budget, applied identically to every cell: **5 rounds, 4096 tokens per round, 300 seconds per
round**, thinking disabled. An item counts as solved only when the submitted output contains the
expected flag; a claim of success without the flag is recorded separately as a hallucination and
never counted as a solve.

### What a rerun will and will not reproduce

The rates in the paper describe the observed outcome of a batch, not a model's success probability.
`solved` is not deterministic: the same model on the same cell flips in a minority of cases (Section
4.3 of the paper, checks C5 and C7). A rerun is expected to land within a few cells of the reported
rate, not on the same 22 cells. What reproduces exactly is the contrast between levels and the
behaviour of the safe control.

## Cost of the batches reported here

| Batch | Cells | Wall clock |
|---|---|---|
| Primary, deepseek-flash, 26 Sep 2026 | 84 (+30 reruns) | about 8 h on a 4-core host |
| qwen3.8-flash, L1 27 Sep 2026 and L0 27 Sep + 8 Oct 2026 | 84 | about 6 h |
| kimi-k3.1-pro, 19 Nov 2026 | 84 | about 2.5 h |
| Repetition, 28 L1 cells × 10 runs | 280 | about 9 h |
| Second host, openEuler 22.03 LTS | 84 | about 8 h |

The API cost was borne by the authors and is not a condition of access to the artifact.
