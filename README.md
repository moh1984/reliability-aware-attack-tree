# Replication Package
## A Reliability-Aware Attack-Tree Framework for Defense-Sensitive Vulnerability Prioritization: Mechanism-Dependent WAF Attenuation

This package reproduces every empirical result in the paper: a **graded** defense
factor *d* measured per attack mechanism across five CWE classes, a corrected and
measured account of stored-XSS WAF bypass, a **held-out transfer validation**
on OWASP Juice Shop, and the statistical comparison against a defense-blind, impact-only baseline.

---

## 1. Requirements

- **`.env`** carries the container image references, so `docker-compose.yml` holds no
  hard-coded tags. It currently ships with the floating tags the published run used
  (`latest` / `stable` / `apache`), which is **not** a pinned environment: those tags
  are reassigned upstream over time. To pin it, run `.\scripts\15_record_digests.ps1`
  after `docker compose up -d` and after `02_zap_scan.ps1` has pulled the ZAP image,
  then copy each digest from `results/IMAGE_DIGESTS.md` into `.env`. That file is
  shipped as a template with blank digests on purpose — a digest is only meaningful
  read off the machine that produced the results, and none was recorded at the time
  of the published run.
- **Docker Desktop** (Windows + WSL2 backend used in the paper) — engine 29.6.2 / Compose v5.3.1 in our run; any recent version works.
- **PowerShell** (the attack scripts are `.ps1`).
- **Python 3.10+** with `numpy` and `scipy` (for the statistics script): `py -m pip install numpy scipy`.
- No local install of ZAP needed — it runs via a Docker image. Exploitation uses scripted curl (PowerShell) only, so that every data point maps to one row of a per-payload matrix; no sqlmap image ships with this package.

## 2. Directory layout

```
reliability-aware-attack-tree/
├── docker-compose.yml        # 4-service testbed (2 targets + 2 WAFs)
├── README.md                 # this file
├── SECURITY_AND_ETHICS.md    # scope / safe-use statement
├── scripts/                  # numbered, run in order
│   ├── 00_setup.ps1          # bring up testbed, capture docker versions, liveness
│   ├── 01_login.ps1          # DVWA login, security=low, emit PHPSESSID
│   ├── 02_zap_scan.ps1       # ZAP baseline on all 4 endpoints
│   ├── 03_sqli.ps1           # graded d, SQL injection (CWE-89)
│   ├── 04_cmdi.ps1           # graded d, command injection (CWE-78)
│   ├── 05_xss_reflected.ps1  # graded d, reflected XSS (CWE-79)
│   ├── 06_xss_stored.ps1     # stored XSS: direct-store AND off-path mechanisms
│   ├── 07_lfi.ps1            # graded d, file inclusion / path traversal (CWE-22)
│   ├── 08_csrf.ps1           # graded d, CSRF (CWE-352)
│   ├── 09_waf_evidence.ps1   # live WAF responses (403 injection vs 200 logic)
│   ├── 10_juiceshop_holdout.ps1  # HELD-OUT validation (breaks circularity)
│   ├── 11_analyze_stats.py   # rank-biserial + bootstrap CI vs exploitability
│   ├── 12_build_master.py    # consolidate matrices -> MASTER_defense_factors.csv
│   ├── 13_sensitivity.py     # sensitivity of the ranking to the reliability weight w
│   ├── 14_sensitivity_impact.py  # sensitivity of the ranking to the impact weights
│   ├── 15_record_digests.ps1 # pin the environment: record the image digests used
│   └── 16_verify_zap.py      # re-derive the ZAP WARN/PASS table from the raw JSON
├── results/                  # outputs land here (reference values included)
│   ├── EXPECTED_RESULTS.md    # values you should reproduce
│   ├── PLACE_YOUR_RAW_FILES_HERE.txt  # what your own run drops here, and where
│   ├── reference_outputs/    # INCLUDED reference CSVs (measured values, script format)
│   ├── zap_*.json            # raw ZAP baseline output for the 4 endpoints, INCLUDED.
│   │                         # Re-derive the WARN/PASS table from them with
│   │                         # scripts/16_verify_zap.py. A re-run overwrites them;
│   │                         # .gitignore deliberately does NOT exclude them.
│   ├── zap_*.html            # the same four scans as human-readable reports
│   ├── zap.yaml              # the ZAP baseline configuration used
│   ├── *_matrix.csv          # per-payload matrices your run produces per class
│   ├── MASTER_defense_factors.csv
│   ├── FINAL_analysis_stats.json
│   ├── sensitivity_analysis.json      # output of 13_sensitivity.py
│   ├── sensitivity_impact.json        # output of 14_sensitivity_impact.py
│   └── IMAGE_DIGESTS.md               # output of 15_record_digests.ps1
│                                      # (shipped as a TEMPLATE: fill it by running
│                                      #  that script on your own machine)
├── workbook/
│   └── model_with_real_data_UPDATED.xlsx   # 7 sheets: d, ranking, hold-out,
│                                           # reliability weights, impact weights,
│                                           # stats, tree-propagation
└── figures/
    ├── figure1_attack_tree.png
    └── figure1_attack_tree.svg
```

> **The paper.** This repository is the replication package accompanying the
> manuscript currently under review, which cites this URL directly. The
> manuscript itself is not included here; the accepted version
> will be added once the publisher's self-archiving policy allows it.

## 3. How to reproduce (in order)

Clone the repository (or unpack the release archive), then open PowerShell in the
`reliability-aware-attack-tree` folder:

```bash
# after cloning this repository:
cd reliability-aware-attack-tree
```

Then, in PowerShell:

```powershell
# one-time per session: allow local scripts to run
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 1. bring up the testbed
.\scripts\00_setup.ps1
#    then in a browser: http://localhost:8081/setup.php -> Create/Reset Database,
#    log in admin/password, DVWA Security = Low

# 2. get a session cookie
.\scripts\01_login.ps1            # copy the printed PHPSESSID
$env:DVWA_SESS = "<paste PHPSESSID here>"

# 3. detection
.\scripts\02_zap_scan.ps1
py .\scripts\16_verify_zap.py   # re-derives the WARN/PASS table from the JSON

# 4. graded exploitation (each writes a per-class matrix CSV + prints d)
.\scripts\03_sqli.ps1
.\scripts\04_cmdi.ps1
.\scripts\05_xss_reflected.ps1
.\scripts\06_xss_stored.ps1
.\scripts\07_lfi.ps1
.\scripts\08_csrf.ps1

# 5. live WAF evidence
.\scripts\09_waf_evidence.ps1

# 6. HELD-OUT validation on Juice Shop (no d re-measurement)
.\scripts\10_juiceshop_holdout.ps1

# 7. consolidate + statistics
py .\scripts\12_build_master.py
py .\scripts\11_analyze_stats.py

# tear down when done
docker compose down -v
```

Compare your `results/` against `results/EXPECTED_RESULTS.md`.

## 4. What each result establishes

| File | Establishes |
|---|---|
| `*_payload_matrix.csv`, `xss_stored_*.csv` | graded d per mechanism (10–20 payloads each) |
| `MASTER_defense_factors.csv` | consolidated d across 5 CWE classes |
| `waf_evidence.txt` | live proof: injection 403, logic 200 |
| `juiceshop_holdout.csv` | d transfers DVWA→Juice Shop (non-circular) |
| `FINAL_analysis_stats.json` | in-sample: ours +1.00 vs impact-only baseline +0.17 (rank-biserial, descriptive) |

## 5. Key findings (see EXPECTED_RESULTS.md for full values)

- **d is mechanism-dependent, not class-dependent.** Reflected and stored XSS share CWE-79 but diverge; command injection is only partially attenuated (d = 0.50): all tested `id` variants bypassed the WAF across separators, while the `echo` variants that succeeded undefended were blocked, so the command—not the separator—decides the bypass. (the tested `whoami`/`uname` requests were rejected with HTTP 403, so the ruleset flags those command tokens, but neither produced a success signal undefended and so neither contributes to d.)
- **Stored-XSS, corrected & measured.** Direct storage through the WAF is *blocked* (403). Response-body inspection is enabled by default in this image; the persisted payload simply was not blocked in the response phase of the tested outbound configuration when served at render.
- **Non-circular validation.** d calibrated on DVWA anticipates WAF behavior on Juice Shop: all four injection-class attacks showed status transitions consistent with WAF intervention (500 -> 400 for the three SQLi payloads, 200 -> 403 for the reflected-XSS payload). This is preliminary out-of-sample evidence for transfer, not a definitive attribution: that would require the matched ModSecurity rule ID from the audit log.
- **In-sample discrimination** (descriptive, not predictive): defense-aware +1.00 vs the defense-blind impact-only baseline +0.17. Independent evidence = the held-out transfer test.

## 6. Notes

- The scripts write into `results/`. Reference copies of the consolidated outputs are included so the package is self-describing even before you run it.
- Exact per-payload numbers can vary by ±1 with image-tag drift (e.g., a CRS ruleset update). The qualitative pattern — injection attenuated, logic/off-path unattenuated — is robust.
- `webgoat` can be added to `docker-compose.yml` as an extra target; it is not required for the paper's results.

## 7. Notes on evidence strength (reviewer-aware)

This package is explicit about what each result does and does not show:

- **In-sample vs. held-out.** The n=7 rank-biserial in `FINAL_analysis_stats.json`
  (and paper Table 5) is an **in-sample descriptive** check: the "ours" score embeds
  the measured d, and the outcome (exploitable-under-defense) is governed by d>0, so a
  strong association is expected by construction. The **independent** evidence is the
  held-out transfer test (`10_juiceshop_holdout.ps1`), where d calibrated on DVWA is
  applied unchanged to Juice Shop.
- **Priority formula is unified.** `11_analyze_stats.py` computes Priority = w x Impact x d,
  identical to paper Table 4. (An earlier draft used d x Impact without w; this is fixed,
  and the impact-only baseline value is +0.167 accordingly.)
- **Stored-XSS mechanism.** This CRS image runs with response-body access enabled by
  default. The measured result is that the stored payload was blocked at direct-store
  time but not in the response phase when served at render — NOT a claim that the WAF
  cannot inspect responses. Set `MODSEC_RESP_BODY_ACCESS=Off`/tighten outbound rules to
  study the render-time factor further.
- **WAF causation / audit log.** A 500->400 or 200->403 transition is strong evidence of
  WAF intervention, but to attribute a block to a specific rule, enable the ModSecurity
  audit log and record the matched rule IDs. This is recommended for a camera-ready run
  and is noted as a limitation in the paper.
- **Detection pipeline.** The released run uses ZAP baseline (passive); leaf evidence for
  exploited nodes comes from the graded exploitation stage. Active scanning
  (`zap-full-scan`) and multi-tool fusion (Nikto/Wapiti) are specified but only partially
  exercised — see paper Sec 5.1.
