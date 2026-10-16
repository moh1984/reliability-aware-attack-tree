#!/usr/bin/env python3
"""
14_sensitivity_impact.py - sensitivity of the ranking to the ORDINAL IMPACT weights.

Companion to 13_sensitivity.py, which perturbs the reliability weight w.
This script perturbs the severity weight Impact instead, and separates two claims
that the paper deliberately keeps apart (see Sec. 3.3 and Sec. 4.6):

  CLAIM A (invariant BY CONSTRUCTION): the exploitable-vs-blocked separation.
          A blocked node has d = 0, so Priority = w * Impact * d = 0 exactly.
          Any strictly positive Impact keeps every survivor above every blocked
          node, so rank-biserial = +1.000 regardless of the weights chosen.

  CLAIM B (genuinely SENSITIVE): the rank order WITHIN the surviving set.
          CSRF and off-path stored XSS are separated by ~1.6%, so small changes
          to Impact reorder them.

Priority(node) = w * Impact * d      (paper Table 4)
Outputs: results/sensitivity_impact.json
"""

import json
import os
import random
from itertools import product

# node, w, Impact, measured d   -- taken from paper Table 4 / MASTER_defense_factors.csv
NODES = [
    ("SQL Injection",         0.85, 0.90, 0.00),
    ("Command Injection",     0.90, 0.95, 0.50),
    ("Reflected XSS",         0.85, 0.60, 0.00),
    ("Stored XSS (direct)",   0.80, 0.60, 0.00),
    ("Stored XSS (offpath)",  0.80, 0.60, 1.00),
    ("File Inclusion",        0.75, 0.70, 0.00),
    ("CSRF",                  0.75, 0.65, 1.00),
]

PERTURBATION = 0.30   # +/- 30% on every Impact value
DRAWS = 5000
SEED = 20250901


def priorities(nodes):
    return [w * imp * d for _, w, imp, d in nodes]


def rank_biserial(scores, exploitable):
    """Continuous score vs binary outcome. +1 = perfect separation."""
    pos = [s for s, e in zip(scores, exploitable) if e]
    neg = [s for s, e in zip(scores, exploitable) if not e]
    if not pos or not neg:
        return None
    wins = sum((p > n) - (p < n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def ordering(names, scores):
    return [n for n, _ in sorted(zip(names, scores), key=lambda z: -z[1])]


def main():
    names = [n for n, _, _, _ in NODES]
    exploitable = [d > 0 for _, _, _, d in NODES]
    survivors = [n for n, e in zip(names, exploitable) if e]

    base = priorities(NODES)
    base_rb = rank_biserial(base, exploitable)
    base_order = [n for n in ordering(names, base) if n in survivors]

    # --- deterministic corners: every Impact simultaneously at low / mid / high
    corners = {}
    for label, factor in (("impact_low", 1 - PERTURBATION),
                          ("impact_mid", 1.0),
                          ("impact_high", 1 + PERTURBATION)):
        pert = [(n, w, min(1.0, imp * factor), d) for n, w, imp, d in NODES]
        corners[label] = rank_biserial(priorities(pert), exploitable)

    # --- random draws: each Impact perturbed independently
    random.seed(SEED)
    rb_values = set()
    top_counts = {n: 0 for n in survivors}
    survivor_orders = {}
    for _ in range(DRAWS):
        pert = [(n, w, max(0.05, min(1.0, imp * random.uniform(1 - PERTURBATION,
                                                               1 + PERTURBATION))), d)
                for n, w, imp, d in NODES]
        sc = priorities(pert)
        rb_values.add(round(rank_biserial(sc, exploitable), 6))
        order = [n for n in ordering(names, sc) if n in survivors]
        top_counts[order[0]] += 1
        survivor_orders[" > ".join(order)] = survivor_orders.get(" > ".join(order), 0) + 1

    # --- closest pair among survivors
    surv_scores = sorted([(n, s) for n, s, e in zip(names, base, exploitable) if e],
                         key=lambda z: -z[1])
    gaps = [(surv_scores[i][0], surv_scores[i + 1][0],
             round((surv_scores[i][1] - surv_scores[i + 1][1]) / surv_scores[i + 1][1] * 100, 2))
            for i in range(len(surv_scores) - 1)]

    out = {
        "priority_formula": "w * Impact * d (paper Table 4)",
        "perturbation": f"+/-{int(PERTURBATION * 100)}% on every Impact value",
        "draws": DRAWS,
        "seed": SEED,
        "baseline": {
            "priorities_under_defense": {n: round(s, 4) for n, s in zip(names, base)},
            "rank_biserial": base_rb,
            "survivor_order": base_order,
        },
        "claim_A_separation_invariant_by_construction": {
            "rank_biserial_corners": corners,
            "rank_biserial_values_over_random_draws": sorted(rb_values),
            "note": ("Blocked nodes score exactly 0 because d = 0, so any strictly "
                     "positive Impact preserves the separation. This is an algebraic "
                     "fact, not an empirical finding; the draws only confirm it."),
        },
        "claim_B_survivor_order_is_sensitive": {
            "closest_pairs_percent_gap": gaps,
            "top_rank_frequency": top_counts,
            "top_rank_share": {n: round(c / DRAWS, 3) for n, c in top_counts.items()},
            "distinct_survivor_orderings": len(survivor_orders),
            "note": ("The rank order among surviving nodes is not robust. The paper "
                     "therefore claims only WHICH nodes survive under defense, and "
                     "treats their relative order as indicative."),
        },
    }

    here = os.path.dirname(os.path.abspath(__file__))
    dest = os.path.join(here, "..", "results", "sensitivity_impact.json")
    dest = os.path.normpath(dest)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps(out, indent=2))
    print(f"\nwritten: {dest}")


if __name__ == "__main__":
    main()
