#!/usr/bin/env python3
"""Regenerate every number reported in the manuscript from the released data.

Each check prints the value recomputed from data/, the value printed in the
paper, and PASS or FAIL. Exit code is 0 only if all checks pass.

    py verify_all_numbers.py            # from the repository root
    py analysis/verify_all_numbers.py

Selection rules (identical to Section 4 of the paper, restated in
docs/METHOD_NOTES.md):

1. Records whose `error` field begins with "INVALID" are dropped. Such a record
   means the run produced no successful round (all API attempts failed), so it
   carries no observation about solvability; the cell was rerun.
2. The primary model's cell value is the last record for that cell in
   data/runs_primary.jsonl. Reruns were issued after Docker infrastructure
   faults, so the last record is the first one that completed.
3. Each secondary model contributes one batch that covers the 42 cells of a
   level: qwen3.8-flash L1 on 2026-09-27, its L0 on 2026-09-27 completed on
   2026-10-08 for the cells the first pass did not reach, kimi-k3.1-pro on
   2026-11-19. No batch is used to overwrite cells of another batch.
4. Cross-model comparison uses the same 42 cells for every model; disagreement
   counts are taken over the intersection.
"""

import collections
import csv
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")

MODELS = ("deepseek_flash", "aliyun_qwen38_flash", "kimi_k31_pro")


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------
def load_jsonl(path):
    rows = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def valid(r):
    return not str(r.get("error") or "").startswith("INVALID")


def cell_map(rows, level, keep="last"):
    """(task, variant) -> solved, dropping INVALID records."""
    out = {}
    for r in rows:
        if r.get("info_level") != level or not valid(r):
            continue
        key = (r["task_id"], r["variant"])
        if keep == "first":
            out.setdefault(key, int(bool(r["solved"])))
        else:
            out[key] = int(bool(r["solved"]))
    return out


def batch_map(rows, model, level, dates=None):
    sel = [r for r in rows
           if r.get("model_key") == model and r.get("info_level") == level and valid(r)]
    if dates:
        sel = [r for r in sel if r["ts"][:10] in dates]
    return cell_map(sel, level, keep="first")


def pct(a, b):
    return round(100.0 * a / b, 1)


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------
class Report(object):
    def __init__(self):
        self.rows = []
        self.failed = 0

    def check(self, cid, where, label, expected, actual, tol=0.0):
        if isinstance(expected, float):
            ok = abs(float(expected) - float(actual)) <= tol + 1e-9
        else:
            ok = expected == actual
        if not ok:
            self.failed += 1
        self.rows.append((cid, where, label, expected, actual, ok))

    def dump(self):
        head = "%-5s %-9s %-52s %-12s %-12s %s" % ("id", "in paper", "quantity", "paper", "recomputed", "status")
        print(head)
        print("-" * len(head))
        for cid, where, label, exp, act, ok in self.rows:
            print("%-5s %-9s %-52s %-12s %-12s %s" % (cid, where, label, exp, act, "PASS" if ok else "FAIL"))
        print("-" * len(head))
        print("%d checks, %d failed" % (len(self.rows), self.failed))
        return 0 if self.failed == 0 else 1


def main():
    prim = load_jsonl(os.path.join(DATA, "runs_primary.jsonl"))
    agent = load_jsonl(os.path.join(DATA, "runs_agent.jsonl"))
    euler = load_jsonl(os.path.join(DATA, "openeuler_runs.jsonl"))

    ds_l1 = cell_map(prim, "L1", "last")
    ds_l0 = cell_map(prim, "L0", "last")
    qw_l1 = batch_map(agent, "aliyun_qwen38_flash", "L1", ("2026-09-27",))
    qw_l0 = batch_map(agent, "aliyun_qwen38_flash", "L0", ("2026-09-27", "2026-10-08"))
    km_l1 = batch_map(agent, "kimi_k31_pro", "L1", None)
    km_l0 = batch_map(agent, "kimi_k31_pro", "L0", None)

    R = Report()
    T1, A, S43, RPT, ENV = "Table 1", "Abstract", "Sec 4.3", "Sec 4.3", "Sec 4.3"

    # ---- A. coverage and criterion -------------------------------------
    R.check("A1", T1, "cells completed (14 x 3 variants x 2 levels)",
            84, len(ds_l1) + len(ds_l0))
    safe_cells = [k for k in list(ds_l1) + list(ds_l0) if k[1] == "safe"]
    safe_solved = sum(ds_l1[k] for k in ds_l1 if k[1] == "safe") + \
                  sum(ds_l0[k] for k in ds_l0 if k[1] == "safe")
    R.check("A2", T1, "safe true-negative cells solved (of 28)",
            0, safe_solved)
    R.check("A2b", T1, "safe true-negative cells present",
            28, len(safe_cells))

    l1_solved, l1_n = sum(ds_l1.values()), len(ds_l1)
    l0_solved, l0_n = sum(ds_l0.values()), len(ds_l0)
    R.check("A3", T1, "L1 solvability, solved cells (of 42)", 22, l1_solved)
    R.check("A3b", T1, "L1 solvability, percent", 52.4, pct(l1_solved, l1_n), 0.05)
    R.check("A4", T1, "L0 solvability, solved cells (of 42)", 2, l0_solved)
    R.check("A4b", T1, "L0 solvability, percent", 4.8, pct(l0_solved, l0_n), 0.05)
    R.check("A12", T1, "solved cells over the full grid (of 84)", 24, l1_solved + l0_solved)

    a_l1 = {k: v for k, v in ds_l1.items() if k[1] == "a"}
    b_l1 = {k: v for k, v in ds_l1.items() if k[1] == "b"}
    R.check("A5", T1, "original variant a solved at L1 (of 14)", 12, sum(a_l1.values()))
    R.check("A5b", T1, "original variant a solve rate, percent", 85.7, pct(sum(a_l1.values()), len(a_l1)), 0.05)
    R.check("A6", T1, "paraphrase variant b solved at L1 (of 14)", 10, sum(b_l1.values()))
    R.check("A6b", T1, "paraphrase variant b solve rate, percent", 71.4, pct(sum(b_l1.values()), len(b_l1)), 0.05)

    l1_solvable_items = sorted(t for (t, v), s in a_l1.items() if s)
    collapse = [t for t in l1_solvable_items if not ds_l0.get((t, "a"), 0)]
    R.check("A7", T1, "L1-solvable items (variant a)", 12, len(l1_solvable_items))
    R.check("A7b", T1, "of those, collapsed to zero at L0", 11, len(collapse))

    # hallucination and cost are read off the 84-row cell matrix
    mrows = list(csv.DictReader(io.open(os.path.join(DATA, "matrix_84cell.csv"), encoding="utf-8")))
    by_level = collections.defaultdict(list)
    for r in mrows:
        by_level[r["info_level"]].append(r)
    l0r, l1r = by_level["L0"], by_level["L1"]
    h0 = sum(int(r["hallucinated"]) for r in l0r)
    h1 = sum(int(r["hallucinated"]) for r in l1r)
    R.check("A8", T1, "hallucination rate at L0, percent", 31.0, pct(h0, len(l0r)), 0.05)
    R.check("A9", T1, "hallucination rate at L1, percent", 9.5, pct(h1, len(l1r)), 0.05)
    tok = sum(int(r["total_tokens"]) for r in l0r) / float(len(l0r))
    rnd = sum(int(r["rounds_used"]) for r in l0r) / float(len(l0r))
    R.check("A10", T1, "mean token consumption at L0", 28767, int(round(tok)))
    R.check("A11", T1, "mean rounds used at L0", 4.8, round(rnd, 1), 0.05)

    # ---- B. cross-model ------------------------------------------------
    R.check("B1", S43, "qwen3.8-flash L1 solved (of 42)", 19, sum(qw_l1.values()))
    R.check("B1b", S43, "qwen3.8-flash L1 rate, percent", 45.2, pct(sum(qw_l1.values()), 42), 0.05)
    R.check("B2", S43, "qwen3.8-flash L0 solved (of 42)", 2, sum(qw_l0.values()))
    R.check("B3", S43, "kimi-k3.1-pro L1 solved (of 42)", 23, sum(km_l1.values()))
    R.check("B3b", S43, "kimi-k3.1-pro L1 rate, percent", 54.8, pct(sum(km_l1.values()), 42), 0.05)
    R.check("B4", S43, "kimi-k3.1-pro L0 solved (of 42)", 3, sum(km_l0.values()))

    common = set(ds_l1) & set(qw_l1) & set(km_l1)
    agree3 = sum(1 for k in common if len({ds_l1[k], qw_l1[k], km_l1[k]}) == 1)
    R.check("B5", S43, "L1 cells, all three models agree", 35, agree3)
    R.check("B5b", S43, "L1 all-three agreement, percent", 83.3, pct(agree3, len(common)), 0.05)
    pair = lambda a, b: sum(1 for k in common if a[k] == b[k])
    R.check("B6", S43, "L1 agreement primary vs kimi (of 42)", 39, pair(ds_l1, km_l1))
    R.check("B7", S43, "L1 agreement qwen vs kimi (of 42)", 38, pair(qw_l1, km_l1))
    R.check("B8", S43, "L1 agreement qwen vs primary (of 42)", 35, pair(qw_l1, ds_l1))

    dis = [k for k in common if len({ds_l1[k], qw_l1[k], km_l1[k]}) > 1]
    R.check("B10", S43, "L1 disagreement cells", 7, len(dis))
    R.check("B10b", S43, "disagreements falling in paraphrase variant b", 4,
            sum(1 for k in dis if k[1] == "b"))
    R.check("B11", S43, "disagreements involving a safe cell", 0,
            sum(1 for k in dis if k[1] == "safe"))

    common0 = set(ds_l0) & set(km_l0)
    agree0 = sum(1 for k in common0 if ds_l0[k] == km_l0[k])
    R.check("B9", S43, "L0 cells, primary and kimi agree (of 42)", 41, agree0)
    R.check("B9b", S43, "L0 two-model agreement, percent", 97.6, pct(agree0, len(common0)), 0.05)

    gaps = []
    for name, l1, l0 in (("primary", ds_l1, ds_l0), ("qwen", qw_l1, qw_l0), ("kimi", km_l1, km_l0)):
        gaps.append(round(pct(sum(l1.values()), len(l1)) - pct(sum(l0.values()), len(l0)), 1))
    R.check("B12", S43, "smallest within-model L1-L0 gap, percentage points", 40.4, min(gaps), 0.05)

    # ---- C. repetition --------------------------------------------------
    qrows = [r for r in agent
             if r.get("model_key") == "aliyun_qwen38_flash" and r.get("info_level") == "L1"
             and r["ts"][:10] in ("2026-11-01", "2026-11-02") and valid(r)]
    bucket = collections.defaultdict(list)
    for r in qrows:
        bucket[(r["task_id"], r["variant"])].append(int(bool(r["solved"])))
    R.check("C1", S43, "qwen repeated subset, cells", 28, len(bucket))
    R.check("C1b", S43, "qwen runs per cell", 10, max(len(v) for v in bucket.values()) if bucket else 0)
    runs = sum(len(v) for v in bucket.values())
    solved_runs = sum(sum(v) for v in bucket.values())
    R.check("C2", S43, "qwen subset solved runs (of 280)", 196, solved_runs)
    R.check("C2b", S43, "qwen subset all-run rate, percent", 70.0, pct(solved_runs, runs), 0.05)
    first = sum(v[0] for v in bucket.values())
    R.check("C3", S43, "qwen subset first-run solved cells (of 28)", 20, first)
    R.check("C3b", S43, "qwen subset first-run rate, percent", 71.4, pct(first, len(bucket)), 0.05)
    R.check("C4", S43, "gap between all-run and first-run rate, points", 1.4,
            round(pct(first, len(bucket)) - pct(solved_runs, runs), 1), 0.05)
    zvar = sum(1 for v in bucket.values() if len(set(v)) == 1)
    R.check("C5", S43, "qwen cells identical across all ten runs", 16, zvar)
    R.check("C5b", S43, "qwen zero-variance share, percent", 57.1, pct(zvar, len(bucket)), 0.05)

    dprim = collections.defaultdict(list)
    for r in prim:
        if r["info_level"] == "L1":
            dprim[(r["task_id"], r["variant"])].append(r)
    rep = {k: v for k, v in dprim.items() if len(v) > 1}
    R.check("C6", S43, "primary model cells with a second or third record", 18, len(rep))
    allruns = sum(len(v) for v in rep.values())
    allsolved = sum(sum(int(bool(x["solved"])) for x in v) for v in rep.values())
    R.check("C6b", S43, "primary rerun records (of 44)", 44, allruns)
    R.check("C6c", S43, "primary rerun all-run solved (of 44)", 22, allsolved)
    R.check("C6d", S43, "primary all-run rate on the subset, percent", 50.0, pct(allsolved, allruns), 0.05)
    R.check("C6e", S43, "primary first-pass solved on the subset (of 18)", 8,
            sum(int(bool(v[0]["solved"])) for v in rep.values()))
    z8 = sum(1 for v in rep.values() if len(set(int(bool(x["solved"])) for x in v)) == 1)
    R.check("C7", S43, "primary cells holding their verdict across all runs", 8, z8)
    R.check("C7b", S43, "primary zero-variance share, percent", 44.4, pct(z8, len(rep)), 0.05)

    fault = sum(1 for v in rep.values()
                if any((x.get("error") or "").strip() for x in v[:-1]))
    R.check("C8", S43, "cells whose rerun followed a logged infrastructure fault", 11, fault)
    R.check("C8b", S43, "cells rerun without a logged error", 7, len(rep) - fault)

    ds_safe = [k for k in rep if k[1] == "safe"]
    R.check("C9", S43, "safe cells inside the primary repeated subset", 5, len(ds_safe))
    R.check("C9b", S43, "solved runs among those safe cells", 0,
            sum(sum(int(bool(x["solved"])) for x in rep[k]) for k in ds_safe))

    def safe_zero(mapping, label_cells=14):
        cells = [k for k in mapping if k[1] == "safe"]
        return len(cells), sum(mapping[k] for k in cells)

    n_q, s_q = safe_zero(qw_l1)
    n_k, s_k = safe_zero(km_l1)
    n_d, s_d = safe_zero(ds_l1)
    R.check("C10", S43, "L1 safe cells present per model", 14, min(n_d, n_q, n_k))
    R.check("C10b", S43, "L1 safe cells solved, three models combined", 0, s_d + s_q + s_k)

    # ---- D. environment replication -------------------------------------
    eul = {(r["task_id"], r["variant"], r["info_level"]): int(bool(r["solved"])) for r in euler}
    pmap = {}
    for k, v in ds_l1.items():
        pmap[(k[0], k[1], "L1")] = v
    for k, v in ds_l0.items():
        pmap[(k[0], k[1], "L0")] = v
    com = set(eul) & set(pmap)
    R.check("D1", ENV, "second-host cells", 84, len(eul))
    R.check("D1b", ENV, "second host L1 solved (of 42)", 22,
            sum(v for (t, v_, l), v in eul.items() if l == "L1"))
    R.check("D1c", ENV, "second host L0 solved (of 42)", 2,
            sum(v for (t, v_, l), v in eul.items() if l == "L0"))
    R.check("D1d", ENV, "second host solved over the full grid (of 84)", 24, sum(eul.values()))
    agr = sum(1 for k in com if eul[k] == pmap[k])
    R.check("D2", ENV, "cells agreeing with the primary host (of 84)", 80, agr)
    R.check("D3", ENV, "disagreeing cells", 4, len(com) - agr)

    # ---- E. released table integrity ------------------------------------
    rebuilt = {}
    for k, v in ds_l1.items():
        rebuilt[(k[0], k[1], "L1")] = v
    for k, v in ds_l0.items():
        rebuilt[(k[0], k[1], "L0")] = v
    shipped = {(r["task_id"], r["variant"], r["info_level"]): int(r["solved"]) for r in mrows}
    R.check("E1", "data file", "matrix_84cell.csv rows", 84, len(mrows))
    R.check("E2", "data file", "matrix_84cell.csv matches a rebuild from runs_primary",
            0, len([k for k in shipped if shipped[k] != rebuilt.get(k)]))

    return R.dump()


if __name__ == "__main__":
    sys.exit(main())
