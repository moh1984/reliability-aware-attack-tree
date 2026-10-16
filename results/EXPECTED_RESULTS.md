# Expected results (reference values from the run of 2026-08-01 / 2026-08-21)

Re-running the scripts on the same image tags should reproduce these values.

## Graded defense factor d (DVWA calibration)

| Node | CWE | Payloads | Succ. undef | Succ. def | d |
|---|---|---|---|---|---|
| SQL Injection | CWE-89 | 20 | 18 | 0 | 0.000 |
| Command Injection | CWE-78 | 13 | 10 | 5 | 0.500 |
| Reflected XSS | CWE-79 | 16 | 16 | 0 | 0.000 |
| Stored XSS (direct store) | CWE-79 | 10 | 10 | 0 | 0.000 |
| Stored XSS (off-path, view via WAF) | CWE-79 | 5 | 5 | 5 | 1.000 |
| File Inclusion | CWE-22 | 10 | 3 | 0 | 0.000 |
| CSRF | CWE-352 | 10 | 10 | 10 | 1.000 |

Command-injection bypass: the `id` command passes regardless of separator (&, ;, |, %0A, CRLF). The `echo` payloads that succeeded undefended were all blocked (403). 5/10 undefended-successful payloads passed the WAF => d=0.50. The COMMAND, not the separator, decides the bypass.
Note on whoami/uname: both were rejected with HTTP 403 (so the ruleset flags those tokens), but neither produced a success signal on the undefended endpoint (undef_hit=0), so neither enters the d computation. The same holds for the `||` echo variant, where the second command does not run.

## ZAP baseline (WARN / PASS)

The four raw reports (`zap_*.json`) are included. WARN is the number of distinct
baseline RULES that fired, not the number of alert entries: one rule can emit
several entries (rule 90004 emits one per Cross-Origin header, rule 10049 one per
cacheability verdict), so counting entries overshoots. WARN + PASS = 67, the size of
the baseline rule set. Run `py scripts/16_verify_zap.py` to re-derive this table.

| Target | Cond | Port | WARN | PASS |
|---|---|---|---|---|
| DVWA | undef | 8081 | 12 | 55 |
| DVWA | def | 9081 | 11 | 56 |
| Juice Shop | undef | 8082 | 8 | 59 |
| Juice Shop | def | 9082 | 8 | 59 |

## Held-out transfer validation (Juice Shop, d NOT re-measured)

All four injection-class attacks showed status transitions consistent with WAF
intervention on the held-out target:
SQLi login (x3): 500 -> 400 ; reflected XSS search: 200 -> 403.
=> consistent with the mechanism-indexed d calibrated on DVWA, i.e. preliminary
   out-of-sample evidence that the factor transfers across target and stack.
   NOT a definitive attribution: the transitions are consistent with a WAF block
   but do not by themselves prove ModSecurity issued it. A camera-ready run should
   enable the audit log and record the matched rule ID per blocked request.

## Live WAF evidence (defended port)

SQLi on 9081  -> HTTP/1.1 403 Forbidden
CSRF on 9081  -> HTTP/1.1 200 OK  (Password Changed: YES)

## Statistics (n=7) — IN-SAMPLE DESCRIPTIVE ONLY

IMPORTANT: This table is an in-sample consistency check, NOT predictive evidence.
The "ours" score embeds the measured d, and the outcome (exploitable-under-defense)
is governed by d>0, so a strong association is expected by construction. The
independent evidence is the held-out transfer test (Juice Shop) above.
With n=7 the bootstrap CI is wide; read point estimates as ordinal.

| Scheme | rank-biserial | 95% CI | Spearman |
|---|---|---|---|
| Ours (reliability + defense-aware) | +1.000 | [+1.00, +1.00] | +0.956 |
| Impact-only baseline (defense-blind) | +0.167 | [-0.80, +1.00] | +0.150 |


## Sensitivity to reliability weight w

Run `python scripts/13_sensitivity.py`. The exploitable-vs-blocked ordering (and the
rank-biserial result) is unchanged when w is drawn from the low, mid, or high end of
each class's benchmark range, because the ordering under defense is dominated by the
measured d, not by w. Output: `results/sensitivity_analysis.json`.
