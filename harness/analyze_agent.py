# -*- coding: utf-8 -*-
"""
Agent 跑批结果分析 —— 产出 T3 / T5 的指标表

用法
    python agent/analyze_agent.py                       # 读默认 runs_agent.jsonl
    python agent/analyze_agent.py --human results/human_baseline.csv  # 并入人类基线, 算 ΔH

输出
    stdout: 分组指标表
    results/agent_summary.md: 可直接贴进论文的表 (markdown)

口径纪律 (与 T1 主线一致)
    1. error != "" 的行一律剔除 (与 runs_real_v2.json 的过滤口径一致)。
    2. 所有速率读作"同预算下的可解率", 不是"能否解出" —— 预算固定为 budget_rounds。
    3. safe 变体的可解率是误报率估计, 不作安全判读; 它只用来证伪判据。
    4. ΔH = 人类解题率 - AI 可解率, 需要外部人类数据; 没有时不计算, 不臆造。
"""

import os
import sys
import json
import argparse
import collections

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)
RESULTS = os.path.join(ROOT, "results")
RUNS = os.path.join(RESULTS, "runs_agent.jsonl")


def load(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows


def rate(num, den):
    return (100.0 * num / den) if den else 0.0


def agg(rows, keyfn):
    """按 keyfn 分组: 返回 {key: {...指标}}"""
    g = collections.OrderedDict()
    for r in rows:
        k = keyfn(r)
        d = g.setdefault(k, {"n": 0, "solved": 0, "claimed": 0, "halluc": 0,
                             "rounds": 0, "tok": 0, "first_round_1": 0,
                             "wall": 0, "err_rounds": 0})
        d["n"] += 1
        d["solved"] += r.get("solved", 0)
        d["claimed"] += r.get("claimed_solved", 0)
        d["halluc"] += r.get("hallucinated", 0)
        d["rounds"] += r.get("rounds_used", 0)
        d["tok"] += r.get("total_tokens", 0)
        d["wall"] += r.get("wall_s", 0)
        d["err_rounds"] += r.get("exec_error_rounds", 0)
        if r.get("first_solve_round") == 1:
            d["first_round_1"] += 1
    return g


def table(title, g, extra_note=""):
    lines = ["### %s%s" % (title, ("  — " + extra_note) if extra_note else ""), ""]
    lines.append("| 分组 | n | 可解率 | 首轮解出 | 声称率 | 幻觉率 | 平均轮数 | 平均token |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for k, d in g.items():
        lines.append("| %s | %d | %.1f%% | %.1f%% | %.1f%% | %.1f%% | %.1f | %d |"
                     % (k, d["n"], rate(d["solved"], d["n"]),
                        rate(d["first_round_1"], d["n"]),
                        rate(d["claimed"], d["n"]), rate(d["halluc"], d["n"]),
                        d["rounds"] / d["n"], d["tok"] / d["n"]))
    lines.append("")
    return "\n".join(lines)


def wilson(k, n, z=1.96):
    """Wilson score 区间 (小样本比 normal approximation 稳)"""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return ((c - m) / d, (c + m) / d)


def _num(x):
    try:
        s = str(x).strip()
        return float(s) if s else None
    except Exception:
        return None


def build_delta_h(path, cross, label=None):
    """
    ΔH = 人类解题率 − AI 可解率。

    溯源门禁 (防自欺的核心):
        一行只有同时满足 (a) human_n>0 且 human_solved<=human_n
        (b) population 非空 (c) source 非空
        才判为 VERIFIED 并进入论文级 ΔH 表; 否则列入"未核验"清单, 不参与任何结论。
    """
    import csv
    verified, unverified = [], []
    with open(path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            tid = (row.get("task_id") or "").strip()
            v = (row.get("variant") or "a").strip()
            if not tid:
                continue
            n = _num(row.get("human_n"))
            k = _num(row.get("human_solved"))
            hr = _num(row.get("human_rate"))
            pop = (row.get("population") or "").strip()
            src = (row.get("source") or "").strip()

            ok = (n is not None and n > 0 and k is not None
                  and 0 <= k <= n and pop and src)
            if hr is None and n and k is not None:
                hr = k / n
            rec = {"tid": tid, "variant": v, "n": int(n or 0), "k": int(k or 0),
                   "rate": hr, "pop": pop, "src": src,
                   "time": _num(row.get("median_time_min"))}
            (verified if ok else unverified).append(rec)

    title = "### T3 核心指标 ΔH = 人类解题率 − AI 可解率"
    if label:
        title += "　（AI 模型 = `%s`）" % label
    lines = [title, ""]
    if not verified:
        lines += ["**无可用的已溯源人类基线**，ΔH 表为空。", ""]
    else:
        lines += ["| 题 | 变体 | 人类解题率 | 95%CI | 人群 | AI 可解率 | ΔH |",
                  "|---|---|---|---|---|---|---|"]
        dhs = []
        for r in sorted(verified, key=lambda x: (x["tid"], x["variant"])):
            rs = cross.get((r["tid"], r["variant"]), [])
            if not rs:
                continue
            ns = sum(x.get("solved", 0) for x in rs)
            ai = ns / len(rs)
            lo, hi = wilson(r["k"], r["n"])
            dh = r["rate"] - ai
            dhs.append(dh)
            lines.append("| %s | %s | %.3f (%d/%d) | [%.2f, %.2f] | %s | %.3f (%d/%d) | %+.3f |"
                         % (r["tid"], r["variant"], r["rate"], r["k"], r["n"],
                            lo, hi, r["pop"], ai, ns, len(rs), dh))
        lines.append("")
        if dhs:
            import statistics
            lines.append("ΔH 均值 %+.3f　中位 %+.3f　范围 [%+.3f, %+.3f]　(n=%d 行)"
                         % (statistics.mean(dhs), statistics.median(dhs),
                            min(dhs), max(dhs), len(dhs)))
            lines.append("")

    lines.append("ΔH < 0 表示 AI 强于人类基线（该题为「反常题」，命题上应淘汰或改造）。")
    lines.append("")
    lines.append("**口径红线**：人类基线与 AI 可解率必须在同一 `variant` 上比较；"
                 "a 与 b 的人类数据须来自同一批受试者（配对设计），否则 ΔH 不可比。")
    lines.append("")

    if unverified:
        lines += ["#### 未核验行（不进入任何结论）", "",
                  "| 题 | 变体 | 缺失项 |", "|---|---|---|"]
        for r in unverified:
            miss = []
            if not (r["n"] and r["k"] is not None):
                miss.append("n/solved")
            if not r["pop"]:
                miss.append("population")
            if not r["src"]:
                miss.append("source")
            lines.append("| %s | %s | %s |" % (r["tid"], r["variant"], ", ".join(miss) or "—"))
        lines.append("")
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=RUNS)
    ap.add_argument("--human", help="人类解题率 CSV: task_id,variant,human_rate")
    ap.add_argument("--out", default=os.path.join(RESULTS, "agent_summary.md"))
    ap.add_argument("--primary", action="store_true",
                    help="每个 (level,task,variant,k) 只保留一个主 run: "
                         "优先 L1fix/L0r1 等 fixed-code tag, 否则取最早有效 run")
    args = ap.parse_args()

    all_rows = load(args.runs)
    rows = [r for r in all_rows if not r.get("error")]
    dropped = len(all_rows) - len(rows)
    if args.primary:
        picked = {}
        for r in rows:
            tag = r["run_id"].rstrip().split("_")[-1]
            fixed = tag.startswith(("L1fix", "L0", "L2"))
            # 注意: 模型必须进去重键。2026-09-27 接入第二条模型线前这里只有
            # (level,task,variant,k), 一旦两个模型跑同一组合就会互相压掉一方的行,
            # 且被保留的一方只取决于 tag/先后 -> "按模型"表会静默变成单模型。
            # model_id 会因回退而与 model_key 不同, 用 model_key 做稳定分组。
            key = (r.get("model_key"), r.get("info_level"),
                   r["task_id"], r["variant"], r.get("k"))
            cur = picked.get(key)
            if cur is None:
                picked[key] = r
            else:
                cur_tag = cur["run_id"].split("_")[-1]
                cur_fixed = cur_tag.startswith(("L1fix", "L0", "L2"))
                if fixed and not cur_fixed:
                    picked[key] = r
        deduped = len(rows) - len(picked)
        rows = list(picked.values())
        dropped += deduped
    if not rows:
        print("无有效行: %s" % args.runs)
        return 1

    out = []
    out.append("# Agent 跑批汇总 (T3 / T5 数据底座)\n")
    out.append("源文件: `%s`　有效行 %d　剔除(error 非空) %d\n"
               % (os.path.basename(args.runs), len(rows), dropped))
    models = sorted(set(r.get("model_id") or r.get("model_key") for r in rows))
    levels = sorted(set(r.get("info_level") for r in rows))
    out.append("模型: %s　信息层级: %s　预算轮数: %s\n"
               % (", ".join(models), ", ".join(levels),
                  ", ".join(str(x) for x in sorted(set(r.get("budget_rounds") for r in rows)))))

    out.append(table("总体", agg(rows, lambda r: "全部")))
    out.append(table("按变体 (a=母题 / b=派生 / safe=真阴性对照)",
                     agg(rows, lambda r: r.get("variant")),
                     "safe 的可解率应接近 0, 否则判据有假阳性"))
    out.append(table("按漏洞族", agg(rows, lambda r: r.get("kind") or "-")))
    out.append(table("按题目", agg(rows, lambda r: r.get("task_id"))))
    if len(levels) > 1:
        out.append(table("按信息层级", agg(rows, lambda r: r.get("info_level"))))
    if len(models) > 1:
        out.append(table("按模型", agg(rows, lambda r: r.get("model_id") or r.get("model_key"))))

    # 变体 x 题目 交叉: T3 判断"派生是否降低可解率"的原始依据
    # 键含模型: 第二个模型进来后必须分模型看, 混合 cells 会在 n 上做平均。
    def mkey(r):
        return r.get("model_key") or "?"

    cross = collections.OrderedDict()
    for r in rows:
        cross.setdefault((mkey(r), r.get("task_id"), r.get("variant")), []).append(r)
    models_multi = len(set(mkey(r) for r in rows)) > 1
    for m in sorted(set(mkey(r) for r in rows)):
        head = "### 题 × 变体 明细 (模型=%s)" % m if models_multi \
            else "### 题 × 变体 明细 (T3 原始依据)"
        lines = [head, "", "| 题 | a | b | safe |", "|---|---|---|---|"]
        for tid in sorted(set(r.get("task_id") for r in rows if mkey(r) == m)):
            cells = []
            for v in ("a", "b", "safe"):
                rs = cross.get((m, tid, v), [])
                if not rs:
                    cells.append("-")
                else:
                    s = sum(x.get("solved", 0) for x in rs)
                    cells.append("%d/%d" % (s, len(rs)))
            lines.append("| %s | %s | %s | %s |" % (tid, cells[0], cells[1], cells[2]))
        lines.append("")
        out.append("\n".join(lines))

    # T3 的 ΔH: 需要外部人类数据, 没有就明确不计算
    # 多模型时逐模型出表: 人类一行对应多个 AI 可解率, 混算会让 ΔH 失真。
    if args.human and os.path.isfile(args.human):
        by_model = sorted(set(k[0] for k in cross))
        for m in by_model:
            sub = {(k[1], k[2]): v for k, v in cross.items() if k[0] == m}
            label = m if len(by_model) > 1 else None
            out.append("\n".join(build_delta_h(args.human, sub, label=label)))
    else:
        out.append("### T3 核心指标 ΔH\n\n"
                   "未接入人类解题率数据 (`--human`), **不计算 ΔH**。\n"
                   "人类基线必须由外部真实数据提供(赛事记录 / 官方数据 / 配对实验), 不得臆造。\n"
                   "模板: `python agent/make_human_template.py`。\n")

    txt = "\n".join(out)
    sys.stdout.write(txt)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(txt)
    sys.stderr.write("\n-> %s\n" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
