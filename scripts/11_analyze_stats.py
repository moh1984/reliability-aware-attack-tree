# 11_analyze_stats.py — correlation of each ranking with actual exploitability under defense.
#
# IMPORTANT (scope): this is an IN-SAMPLE DESCRIPTIVE check, not predictive validation.
# The "ours" score embeds the measured d, and the outcome (exploitable-under-defense)
# is governed by d>0, so a strong association is expected by construction. The
# independent evidence is the held-out transfer test (10_juiceshop_holdout.ps1).
#
# Priority(node) = w x Impact x d   (matches paper Table 4 exactly)
# Impact-only baseline = the severity weight used alone (defense-blind: ignores d).
# It is deliberately NOT called a CVSS baseline: Impact is an ordinal severity
# weight (paper Sec 3.3), not an official CVSS score.
#
# Binary ground truth -> rank-biserial + bootstrap 95% CI (Spearman shown for reference).

import numpy as np, json, os
from pathlib import Path
_RES = Path(__file__).resolve().parent.parent / 'results'
_RES.mkdir(exist_ok=True)
try:
    from scipy import stats
    HAVE_SCIPY=True
except ImportError:
    HAVE_SCIPY=False

# node, cwe, mechanism, reliability weight w, impact (scaled 0-1), measured d, exploitable-under-defense (0/1)
# w and impact are taken EXACTLY from paper Table 4 so this script reproduces that table.
data=[
 ("SQL Injection",        "CWE-89","direct-injection",   0.85, 0.90, 0.000, 0),
 ("Command Injection",    "CWE-78","direct-injection",   0.90, 0.95, 0.500, 1),
 ("Reflected XSS",        "CWE-79","reflected",          0.85, 0.60, 0.000, 0),
 ("Stored XSS (direct)",  "CWE-79","persisted-direct",   0.80, 0.60, 0.000, 0),
 ("Stored XSS (offpath)", "CWE-79","persisted-offpath",  0.80, 0.60, 1.000, 1),
 ("File Inclusion",       "CWE-22","path-traversal",     0.75, 0.70, 0.000, 0),
 ("CSRF",                 "CWE-352","logic",             0.75, 0.65, 1.000, 1),
]
nodes=[r[0] for r in data]
w    =np.array([r[3] for r in data])
imp  =np.array([r[4] for r in data])
d    =np.array([r[5] for r in data])
truth=np.array([r[6] for r in data])

ours_def   = w*imp*d          # our priority UNDER defense (Table 4 "Ours (def.)")
ours_undef = w*imp            # our priority undefended (d=1)  (Table 4 "Ours (undef.)")
base_pri   = imp              # defense-blind baseline (Table 4 "Impact-only baseline")

def rb(scores,y):
    y=np.array(y); s=np.array(scores); pos=s[y==1]; neg=s[y==0]
    if len(pos)==0 or len(neg)==0: return np.nan
    gt=sum(p>n for p in pos for n in neg); lt=sum(p<n for p in pos for n in neg)
    return (gt-lt)/(len(pos)*len(neg))

def boot(scores,y,n=5000):
    y=np.array(y); s=np.array(scores); idx=np.arange(len(y)); rng=np.random.default_rng(42); v=[]
    for _ in range(n):
        k=rng.choice(idx,len(idx),replace=True)
        if len(set(y[k]))<2: continue
        v.append(rb(s[k],y[k]))
    return (float(np.percentile(v,2.5)),float(np.percentile(v,97.5))) if v else (np.nan,np.nan)

rb_o,rb_c=rb(ours_def,truth),rb(base_pri,truth)
ci_o,ci_c=boot(ours_def,truth),boot(base_pri,truth)
sp_o=stats.spearmanr(ours_def,truth).correlation if HAVE_SCIPY else None
sp_c=stats.spearmanr(base_pri,truth).correlation if HAVE_SCIPY else None

print(f"{'node':22}{'w':>5}{'imp':>6}{'d':>6}{'ours_def':>10}{'imp_only':>10}{'exploit':>9}")
for i,nm in enumerate(nodes):
    print(f"{nm:22}{w[i]:>5.2f}{imp[i]:>6.2f}{d[i]:>6.2f}{ours_def[i]:>10.3f}{base_pri[i]:>10.3f}{truth[i]:>9d}")

print("\n=== IN-SAMPLE discrimination vs exploitability under defense (n=7) ===")
print("NOTE: descriptive only; see held-out test for predictive evidence.")
print(f"OURS  rank-biserial={rb_o:+.3f}  95%CI[{ci_o[0]:+.2f},{ci_o[1]:+.2f}]  spearman={sp_o}")
print(f"IMPACT-ONLY  rank-biserial={rb_c:+.3f}  95%CI[{ci_c[0]:+.2f},{ci_c[1]:+.2f}]  spearman={sp_c}")

json.dump({"scope":"in-sample descriptive (not predictive)",
           "priority_formula":"w*Impact*d (matches paper Table 4)",
           "ours_rank_biserial":rb_o,"ours_CI":list(ci_o),
           "impact_only_rank_biserial":rb_c,"impact_only_CI":list(ci_c),
           "ours_spearman":sp_o,"impact_only_spearman":sp_c,
           "baseline_note":"the baseline is the ordinal severity weight used alone, not an official CVSS score",
           "n":len(nodes)},
          open(_RES / "FINAL_analysis_stats.json","w"),indent=2,default=str)
print(f"\nSaved {_RES / 'FINAL_analysis_stats.json'}")
