# 12_build_master.py — consolidate per-class matrices into MASTER_defense_factors.csv
#
# Source resolution (this is what makes the package self-contained):
#   1. results/<file>.csv                     <- YOUR run, if you executed 03..10
#   2. results/reference_outputs/<file>.csv   <- the reference values shipped with
#                                                the package, in the same format
# The chosen source is printed per class, so reference values can never be
# mistaken for a fresh run.
import csv
import os
from pathlib import Path

R = Path(__file__).resolve().parent.parent / "results"
REF = R / "reference_outputs"


def resolve(f):
    """Prefer the user's own run; fall back to the shipped reference outputs."""
    if (R / f).exists():
        return R / f, "your run"
    if (REF / f).exists():
        return REF / f, "reference"
    return None, None


def summ(f, uc, dc):
    p, src = resolve(f)
    if p is None:
        return None
    rows = list(csv.DictReader(open(p, encoding='utf-8-sig')))
    nU = sum(1 for r in rows if r.get(uc) == "1")
    nD = sum(1 for r in rows if r.get(dc) == "1")
    # d is defined over the payloads that succeeded WITHOUT the WAF; payloads that
    # fail undefended carry no information about the effect of the WAF.
    d = round(nD / nU, 3) if nU else None
    return (len(rows), nU, nD, d, src)


out = [("Node", "CWE", "Mechanism", "AccessPath",
        "Payloads", "SuccUndef", "SuccDef", "d")]
specs = [
    ("SQL Injection", "CWE-89", "direct injection", "inbound-inspected",
     "sqli_payload_matrix.csv", "undef_hit", "def_hit"),
    ("Command Injection", "CWE-78", "direct injection", "inbound-inspected",
     "cmdi_payload_matrix.csv", "undef_hit", "def_hit"),
    ("Reflected XSS", "CWE-79", "reflected", "inbound-inspected",
     "xss_reflected_matrix.csv", "undef_hit", "def_hit"),
    ("Stored XSS (direct)", "CWE-79", "persisted direct", "inbound-inspected",
     "xss_stored_matrix.csv", "rendered_U", "rendered_D"),
    ("File Inclusion", "CWE-22", "path traversal", "inbound-inspected",
     "lfi_matrix.csv", "undef_hit", "def_hit"),
    ("CSRF", "CWE-352", "logic", "not-injection-signature",
     "csrf_matrix.csv", "undef_hit", "def_hit"),
]

sources = []
for nm, cwe, mech, ap, f, uc, dc in specs:
    s = summ(f, uc, dc)
    if s:
        out.append((nm, cwe, mech, ap, s[0], s[1], s[2], s[3]))
        sources.append((nm, s[4]))
    else:
        print(f"  MISSING: {f} (neither results/ nor results/reference_outputs/)")

# off-path stored XSS: planted via the undefended port, then rendered through the WAF
p, src = resolve("xss_stored_crossport.csv")
if p is not None:
    rows = list(csv.DictReader(open(p, encoding='utf-8-sig')))
    ns = sum(1 for r in rows if r.get("payload_served_through_WAF") == "1")
    out.append(("Stored XSS (off-path)", "CWE-79", "persisted off-path",
                "outbound-not-blocked", len(rows), len(rows), ns,
                round(ns / len(rows), 3) if rows else None))
    sources.append(("Stored XSS (off-path)", src))

dest = R / "MASTER_defense_factors.csv"
with open(dest, "w", newline='', encoding='utf-8') as fh:
    csv.writer(fh).writerows(out)

for r in out:
    print(r)
print("\nsource per class:")
for nm, src in sources:
    print(f"  {nm:24s} {src}")
if any(src == "reference" for _, src in sources):
    print("\nNOTE: at least one class used the shipped reference outputs, not a fresh run.")
print(f"\nSaved {dest}")
