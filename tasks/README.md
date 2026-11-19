# Benchmark

Fourteen executable challenges, each a self-contained HTTP service that can be
started from the command line, plus the JSON contract the harness reads.

## The fourteen challenges that were actually measured

| id | scenario | CWE | attack surface | variants |
|---|---|---|---|---|
| `t01` | login check | CWE-89 | SQL injection | a / b / safe |
| `t02` | file download | CWE-22 | path traversal | a / b / safe |
| `t03` | template rendering | CWE-94 | server-side template injection | a / b / safe |
| `t04` | config loading | CWE-502 | unsafe deserialisation | a / b / safe |
| `t05` | echo service | CWE-78 | OS command injection | a / b / safe |
| `t06` | remote fetch | CWE-918 | SSRF | a / b / safe |
| `t07` | password reset | CWE-338 | weak random token | a / b / safe |
| `t08` | profile lookup | CWE-639 | IDOR / broken access control | a / b / safe |
| `t09` | health endpoint | CWE-200 | information exposure | a / b / safe |
| `t10` | online calculator | CWE-95 | expression-eval injection | a / b / safe |
| `t11` | signal relay | CWE-95 | second-order eval injection | a / b / safe |
| `t12` | message board | CWE-89 | constrained SQL injection | a / b / safe |
| `t13` | notification service | CWE-78 | blacklist-filtered command injection | a / b / safe |
| `t14` | card renderer | CWE-918 | SSRF | a / b / safe |

`t01`–`t10` are our own constructed challenges, one per CWE class. They validate
the oracle (Sec. V-A–V-D of the paper) and form the main real-model group
(Sec. V-G). `t11`–`t14` are semantic re-implementations of four HITCON CTF web
challenges, forming the external group (Sec. V-H). Provenance for every
challenge, and for the corpora behind them, is in `../SOURCES.md`.

## `task.json` — the contract

Everything the harness needs to judge a challenge, and nothing else. Taking
`t01_sqli` as the example:

```json
{
  "id": "t01",
  "name": "登录校验（SQL 注入）",
  "cwe": "CWE-89",
  "flag": "flag{sqli_basic_2026}",
  "endpoint": "/login",
  "method": "POST",
  "params": ["user", "pass"],
  "aliases": {
    "path": ["/login", "/signin", "/auth", "/login.php"],
    "param": {
      "user": ["user", "username", "name", "u"],
      "pass": ["pass", "password", "pwd", "p"]
    }
  },
  "exploit": {"kind": "sqli"},
  "functional": [
    {"name": "login_ok",  "path": "/login", "method": "POST",
     "form": {"user": "alice", "pass": "alice123"},
     "expect_status": 200, "expect_contains": "welcome"},
    {"name": "login_bad", "path": "/login", "method": "POST",
     "form": {"user": "alice", "pass": "wrong"},
     "expect_status": 401, "expect_contains": "denied"}
  ]
}
```

| field | role |
|---|---|
| `endpoint`, `method`, `params` | the **reference interface** `R` — what the model is told, and what a `base`-mode exploit uses |
| `aliases.path`, `aliases.param` | the vocabulary the **adaptive layer** may search; this is what absorbs interface drift |
| `functional` | the functional channel: named test cases with an expected status and a required substring |
| `exploit.kind` | which attack class in `exploits.py` to use |
| `flag` | the oracle's success token — the exploit must retrieve exactly this string |

The separation matters: `aliases` is what makes the oracle answer "is the defect
reachable" instead of "does the code look like the reference". An exploit run
without it (`base` mode) only speaks the reference vocabulary and scores 0 % on
interface-drifted code — the drift cost the paper quantifies.

## Implementation variants

Each `impl.py` accepts `--variant a|b|safe` and serves one of three shapes:

| variant | semantics | interface | expected verdict |
|---|---|---|---|
| `a` | vulnerable | matches the task statement | should be exploitable |
| `b` | vulnerable | route **and** parameter names rewritten | should still be exploitable (drift-robustness check) |
| `safe` | patched | matches the task statement | **must not** be exploitable (false-positive control) |

The 20 `safe` variants are what make `FPR = 0 / 20` a measured quantity rather
than an assumption. `a` and `b` differ only in naming, so any verdict difference
between them is attributable to interface drift and nothing else.

Convention that trips people up: in variant `a` the actual parameter names must
equal the **logical names** in `task.json` (`expr` for eval, `host` for command
injection, `user`/`pass` for SQLi, `url` for SSRF). `base` mode tries only those
logical names, so a test implementation that renames its own parameters inside
variant `a` will silently score zero exploitable.

The same rule limits the adaptive search: `harness.py` expands at most the first
six alias combinations per parameter, so keep each parameter's alias list to
three or fewer entries. Longer lists get truncated, which silently drops the
variant-`b` parameter pairs and zeroes the functional channel.

## Running one challenge by hand

```bash
cd ..                                       # repository root
python validate_ref.py t01 a                # should be exploited
python validate_ref.py t01 safe             # should not be
python validate_ext.py t11 t12 t13 t14      # the external group
```

## What is *not* here

* **Corpus A sources** (SUSCTF 2021/2022) — third-party, not redistributed. We
  cite and re-implement the defence shapes; the originals live at the upstream
  links in `../SOURCES.md`.
* **Corpus B challenge material** — obtained privately; not in this repository,
  and no measured result depends on it.
* **The L2 derived families.** The paper's benchmark *design* is 58 items
  (L1 15 mother challenges + L2 43 derived families, Table IV). This repository
  carries the L1 implementations that the reported experiments ran against;
  expanding L1 to its full extent with pinned snapshots and larger `k` is listed
  as outstanding work in the paper's conclusion.
* **Original HITCON sources** — same reasoning as Corpus A; `t11..t14/` are our
  Python re-implementations.
