r"""Derive the released data files from the laboratory's raw run logs.

Run once by the authors when cutting a release; reviewers do not need to run it.
It (a) keeps only the three models reported in the paper, (b) drops the aborted
fourth-model batch, (c) replaces machine-local absolute paths with <workdir>,
and (d) writes the 84-row cell matrix used by the analysis scripts.

    py prepare_release.py --raw  ../../../DSA\ 2026\ 厦门/ctf-oracle/results ^
                          --prim ../../../output/<run>/working/pkg/data ^
                          --out  ../data
"""

import argparse
import collections
import csv
import io
import json
import os
import re
import sys

# Models reported in the manuscript. The GLM batch was abandoned (endpoint
# timeouts, invalid records) and is not part of any reported number.
KEEP_MODELS = ("deepseek_flash", "aliyun_qwen38_flash", "kimi_k31_pro")

# Machine-local paths that must not travel with the release.
PATH_PATTERNS = [
    re.compile(r"[A-Za-z]:\\+Users\\+[^\\\s\"']+"),
    re.compile(r"[A-Za-z]:\\+[^\s\"']*?AppData[^\s\"']*"),
    re.compile(r"/home/[A-Za-z0-9_.-]+"),
    re.compile(r"/tmp/[A-Za-z0-9_.-]+"),
]


def scrub(obj):
    """Recursively replace machine-local absolute paths inside a record."""
    if isinstance(obj, str):
        s = obj
        for pat in PATH_PATTERNS:
            s = pat.sub("<workdir>", s)
        return s
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    return obj


def load_jsonl(path):
    out = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def dump_jsonl(path, rows):
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(scrub(r), ensure_ascii=False, sort_keys=True) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, help="folder with runs_agent.jsonl / rounds_agent.jsonl")
    ap.add_argument("--prim", required=True, help="folder with runs_primary.jsonl / matrix_84cell.csv")
    ap.add_argument("--euler", help="folder with openEuler full-run jsonl")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    runs = [r for r in load_jsonl(os.path.join(a.raw, "runs_agent.jsonl"))
            if r.get("model_key") in KEEP_MODELS]
    # per-round records carry the model only inside run_id, e.g.
    # aliyun_qwen38_flash_t01_a_k1_L1r1_part02; match on the longest prefix.
    rounds = []
    for r in load_jsonl(os.path.join(a.raw, "rounds_agent.jsonl")):
        rid = str(r.get("run_id", ""))
        if any(rid.startswith(m + "_") for m in KEEP_MODELS):
            rounds.append(r)

    # normalise: keep argument order, drop the local-only final_src blob into a
    # separate field so the record stays readable, keep everything else.
    dump_jsonl(os.path.join(a.out, "runs_agent.jsonl"), runs)
    dump_jsonl(os.path.join(a.out, "rounds_agent.jsonl"), rounds)

    prim = load_jsonl(os.path.join(a.prim, "runs_primary.jsonl"))
    dump_jsonl(os.path.join(a.out, "runs_primary.jsonl"), prim)

    for name in ("matrix_84cell.csv", "summary_counts.csv"):
        src = os.path.join(a.prim, name)
        if os.path.exists(src):
            with io.open(src, encoding="utf-8-sig") as fh:
                body = fh.read()
            with io.open(os.path.join(a.out, name), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(body.lstrip("\ufeff"))

    if a.euler:
        eul = [r for r in load_jsonl(os.path.join(a.euler, "openEuler全量runs_2026-09-30.jsonl"))]
        dump_jsonl(os.path.join(a.out, "openeuler_runs.jsonl"), eul)

    print("runs_agent.jsonl     %5d records  %s" % (len(runs), dict(collections.Counter(r["model_key"] for r in runs))))
    print("rounds_agent.jsonl   %5d records" % len(rounds))
    print("runs_primary.jsonl   %5d records" % len(prim))
    return 0


if __name__ == "__main__":
    sys.exit(main())
