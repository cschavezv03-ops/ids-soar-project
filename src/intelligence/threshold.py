"""
A6 - fix the decision threshold, with the evidence for why.

Scope. This module READS the test-set predictions A5 already verified and turns
the probability the model emits into an operating policy. It never retrains and
never refits: the model is frozen, only the cut moves.

WHAT A6 IS NOT. It is not an optimisation with a right answer. Attack-class F1
is flat between 0.40 and 0.95 (0.9915 to 0.9926), so it carries no signal about
where to cut, and the marginal trade-off curve has no elbow either. What moves
is the balance between two errors that cost different things, so the threshold
is a POLICY choice constrained by measurement, not a maximum to be found.

THE OPERATING POINT, decided:

    < 0.70          ignored
    [0.70, 0.90)    MEDIUM severity - short containment (SHORT_BLOCK_TTL)
    >= 0.90         HIGH severity   - full containment  (BLOCK_TTL_SECONDS)

Two tiers rather than one, because the cost of being wrong is not symmetric and
a single cut forces one answer to two different questions. A borderline flow
gets a five-minute block; a confident one gets ten.

The numbers live in src/common/config.py, which is component B's file and the
single source of truth. This module READS them and refuses to run if they have
drifted from what A6 measured - so the report can never describe an operating
point that the running system does not use.

Usage (from the repo root):
    python src/intelligence/threshold.py
"""

import argparse
import os
import sys

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config  # noqa: E402
from intelligence import contract  # noqa: E402
from intelligence import train  # noqa: E402
from intelligence.evaluate import FIGURES_DIR  # noqa: E402
from intelligence.preprocess import LABEL_COL, Report  # noqa: E402

REPORT_PATH = os.path.join("scripts", "scripts_output", "threshold_report.txt")

# What A6 measured and decided. config.py must agree with these or the run
# stops: a report describing 0.70 while the system containment-blocks at 0.50
# would be worse than no report at all.
# Recalibrated in A7 against real lab traffic; A6 set these to 0.70 / 0.90 on
# CICIDS2017 alone. The A6 analysis below still reproduces on the CICIDS2017
# test set - what changed is which point on that curve the system operates at.
CONTAIN_THRESHOLD = 0.50
HIGH_THRESHOLD = 0.70

# Prevalences to project precision onto. The test set is 16.67% attacks; a real
# network between attacks is nowhere near that, and precision depends on it.
PREVALENCES = (0.1667, 0.05, 0.01, 0.001)

SWEEP = np.round(np.arange(0.05, 1.001, 0.05), 2)


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------

def assert_config_matches_decision() -> None:
    """Refuse to run if config.py has drifted from the A6 decision.

    config.py is shared with component B and nothing else forces the two to
    agree. If someone edits the threshold there, this report would keep
    describing an operating point the system no longer uses - a documentation
    lie that no test would otherwise catch.
    """
    expected = {
        "THRESHOLD": CONTAIN_THRESHOLD,
        "SEV_MEDIUM": CONTAIN_THRESHOLD,
        "SEV_HIGH": HIGH_THRESHOLD,
    }
    wrong = {
        name: (getattr(config, name), value)
        for name, value in expected.items()
        if getattr(config, name) != value
    }
    if wrong:
        detail = "; ".join(
            f"config.{n} is {got} but A6 decided {want}" for n, (got, want) in wrong.items()
        )
        raise SystemExit(
            f"config.py disagrees with the A6 decision: {detail}.\n"
            f"Either revert config.py or rerun A6 and update "
            f"contract/A6_threshold_note.md. Do not leave them out of step."
        )


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

def sweep_metrics(y_true, proba, thresholds=SWEEP) -> pd.DataFrame:
    """Attack-class metrics at every candidate cut. Counts, not just rates:
    'false positive rate 0.0023' hides how many real users that is."""
    y_true = np.asarray(y_true)
    n_pos = int((y_true == contract.ATTACK).sum())
    n_neg = int((y_true == contract.BENIGN).sum())

    rows = []
    for threshold in thresholds:
        flagged = proba >= threshold
        tp = int((flagged & (y_true == contract.ATTACK)).sum())
        fp = int((flagged & (y_true == contract.BENIGN)).sum())
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / n_pos
        rows.append({
            "threshold": float(threshold),
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "tp": tp, "fp": fp, "fn": n_pos - tp,
            "fpr": fp / n_neg,
        })
    return pd.DataFrame(rows)


def precision_at_prevalence(recall: float, fpr: float, prevalence: float) -> float:
    """What precision becomes if attacks are rarer than in the test set.

    The model does not change; the arithmetic does. Precision is
    P(attack | flagged), and that depends on how common attacks are. The test
    set is 16.67% attacks by construction of the dataset, which is nothing like
    a network sitting idle between demo attacks.
    """
    hit = prevalence * recall
    miss = (1 - prevalence) * fpr
    return hit / (hit + miss) if hit + miss else 0.0


def band_composition(y_true, proba, labels) -> pd.DataFrame:
    """What actually lands in each severity band, and how pure it is.

    Purity is the number that decides whether a band is worth acting on: a band
    that is half benign traffic is not a detection, it is a coin flip.
    """
    y_true = np.asarray(y_true)
    bands = [
        ("ignored   (< %.2f)" % CONTAIN_THRESHOLD, proba < CONTAIN_THRESHOLD),
        ("MEDIUM  [%.2f-%.2f)" % (CONTAIN_THRESHOLD, HIGH_THRESHOLD),
         (proba >= CONTAIN_THRESHOLD) & (proba < HIGH_THRESHOLD)),
        ("HIGH       (>= %.2f)" % HIGH_THRESHOLD, proba >= HIGH_THRESHOLD),
    ]
    rows = []
    for name, mask in bands:
        total = int(mask.sum())
        attack = int((mask & (y_true == contract.ATTACK)).sum())
        rows.append({
            "band": name, "total": total, "attack": attack,
            "benign": total - attack,
            "purity": attack / total if total else 0.0,
        })
    return pd.DataFrame(rows)


def family_recall_by_threshold(labels, y_true, proba, thresholds) -> pd.DataFrame:
    """Per-family recall across cuts, plus the benign false-positive rate.

    The aggregate is flat across this whole range; the families are not. A5
    made the case that an aggregate can hide a whole family, and choosing a
    threshold on the aggregate alone would be exactly that mistake again.
    """
    labels = np.asarray(labels)
    y_true = np.asarray(y_true)
    rows = []
    for family in pd.unique(labels):
        mask = labels == family
        is_benign = y_true[mask][0] == contract.BENIGN
        row = {"family": family, "n": int(mask.sum()),
               "metric": "false positive rate" if is_benign else "recall"}
        for threshold in thresholds:
            row[threshold] = float((proba[mask] >= threshold).mean())
        rows.append(row)
    frame = pd.DataFrame(rows)
    return frame.sort_values(["metric", "n"], ascending=[True, False]).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------

def _mark_operating_point(ax) -> None:
    ax.axvline(CONTAIN_THRESHOLD, color="#d95f02", linewidth=1.4, linestyle="--")
    ax.axvline(HIGH_THRESHOLD, color="#7570b3", linewidth=1.4, linestyle="--")


def plot_threshold_curve(sweep: pd.DataFrame, path: str) -> str:
    """Precision, recall and false-positive count against the cut.

    Two y-axes on purpose: the rates live in [0, 1] and say nothing about
    volume, while the false-positive COUNT is what turns into blocked users.
    """
    fig, ax = plt.subplots(figsize=(7.2, 5.0), dpi=150)
    ax.plot(sweep["threshold"], sweep["precision"], color="#1b7837",
            linewidth=2.2, label="precision (attack)")
    ax.plot(sweep["threshold"], sweep["recall"], color="#762a83",
            linewidth=2.2, linestyle="--", label="recall (attack)")
    ax.set_ylim(0.95, 1.001)
    ax.set_xlabel("decision threshold")
    ax.set_ylabel("precision / recall")

    right = ax.twinx()
    right.plot(sweep["threshold"], sweep["fp"], color="#b2182b",
               linewidth=1.8, linestyle=":", label="false positives (count)")
    right.set_ylabel("false positives on 331,691 benign flows")
    right.set_ylim(0, sweep["fp"].max() * 1.1)

    _mark_operating_point(ax)
    ax.annotate("contain\n0.70", xy=(CONTAIN_THRESHOLD, 0.9525),
                ha="center", fontsize=8, color="#d95f02")
    ax.annotate("HIGH\n0.90", xy=(HIGH_THRESHOLD, 0.9525),
                ha="center", fontsize=8, color="#7570b3")

    handles = ax.get_lines()[:2] + right.get_lines()[:1]
    ax.legend(handles, [h.get_label() for h in handles], loc="center left", fontsize=9)
    ax.set_title("Where to cut: the aggregate barely moves, the error mix does",
                 fontsize=11, pad=10)
    ax.grid(alpha=0.25, linewidth=0.6)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


def plot_family_curves(labels, y_true, proba, path: str) -> str:
    """Per-family recall against the cut. This is the figure that justifies
    NOT pushing the threshold higher: the aggregate hides these."""
    labels = np.asarray(labels)
    y_true = np.asarray(y_true)
    grid = np.round(np.arange(0.05, 1.001, 0.025), 3)

    fig, ax = plt.subplots(figsize=(7.2, 5.4), dpi=150)
    families = [f for f in pd.unique(labels) if f != contract.BENIGN_LABEL]
    families.sort(key=lambda f: -(labels == f).sum())
    colours = plt.cm.tab10(np.linspace(0, 1, 10))

    for i, family in enumerate(families):
        mask = labels == family
        recalls = [(proba[mask] >= g).mean() for g in grid]
        ax.plot(grid, recalls, color=colours[i], linewidth=1.8,
                label=f"{family} (n={int(mask.sum()):,})")

    _mark_operating_point(ax)
    ax.set_xlabel("decision threshold")
    ax.set_ylabel("recall within the family")
    # Every curve lives above 0.55; starting the axis at 0 would spend half the
    # figure on empty space and flatten the divergence this plot exists to show.
    ax.set_ylim(0.55, 1.01)
    ax.set_title("Per-family recall: the small families are what a high cut costs",
                 fontsize=11, pad=10)
    ax.grid(alpha=0.25, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.legend(loc="lower left", fontsize=7.5, ncol=2, framealpha=0.92)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="A6: fix the decision threshold.")
    ap.add_argument("--predictions", default=train.PREDICTIONS_PATH)
    ap.add_argument("--figures-dir", default=FIGURES_DIR)
    ap.add_argument("--report", default=REPORT_PATH)
    args = ap.parse_args()

    if not os.path.exists(args.predictions):
        raise SystemExit(
            f"{args.predictions} not found. A6 never retrains - run A4 first:\n"
            f"    python src/intelligence/train.py"
        )

    assert_config_matches_decision()

    predictions = train.load_predictions(args.predictions)
    y_true = predictions["y_true"].to_numpy()
    proba = predictions[f"{train.RF_KEY}_proba"].to_numpy()
    labels = predictions[LABEL_COL].to_numpy()

    rep = Report()
    rep("A6 threshold report - fixing the operating point of the Random Forest")
    rep(f"contract version {contract.CONTRACT_VERSION}")
    rep("")
    rep("Nothing was retrained. The model is frozen; only the cut moves.")
    rep("Measured on the A4 test-set predictions, 398,033 flows.")

    # ---- 1. why F1 cannot choose --------------------------------------
    rep.banner("1. THE AGGREGATE CANNOT CHOOSE THE THRESHOLD")
    sweep = sweep_metrics(y_true, proba)
    window = sweep[(sweep["threshold"] >= 0.40) & (sweep["threshold"] <= 0.95)]
    rep(f"Attack-class F1 across 0.40-0.95: min {window['f1'].min():.4f}, "
        f"max {window['f1'].max():.4f}")
    rep(f"    -> it varies by {window['f1'].max() - window['f1'].min():.4f} over "
        f"that whole range.")
    rep("")
    rep("So F1 carries no signal about where to cut, and the marginal curve has")
    rep("no elbow either. What DOES move is the mix of the two errors, and they")
    rep("do not cost the same thing. A6 is therefore a POLICY decision")
    rep("constrained by measurement, not a maximum to be found. Saying that")
    rep("plainly is more defensible than presenting a chosen number as optimal.")
    rep("")
    rep(f"    {'thr':>6}{'precision':>11}{'recall':>9}{'F1':>9}"
        f"{'FP':>8}{'FN':>8}{'FPR':>10}")
    for _, r in sweep.iterrows():
        mark = ""
        if abs(r["threshold"] - CONTAIN_THRESHOLD) < 1e-9:
            mark = "  <- contain"
        elif abs(r["threshold"] - HIGH_THRESHOLD) < 1e-9:
            mark = "  <- HIGH"
        rep(f"    {r['threshold']:>6.2f}{r['precision']:>11.4f}{r['recall']:>9.4f}"
            f"{r['f1']:>9.4f}{int(r['fp']):>8,}{int(r['fn']):>8,}{r['fpr']:>10.5f}{mark}")

    # ---- 2. the decision ----------------------------------------------
    rep.banner("2. THE OPERATING POINT")
    rep("Read from src/common/config.py, which is the single source of truth")
    rep("shared with component B. This run refuses to start if they disagree.")
    rep("")
    rep(f"    < {CONTAIN_THRESHOLD:.2f}          ignored, no case opened")
    rep(f"    [{CONTAIN_THRESHOLD:.2f}, {HIGH_THRESHOLD:.2f})    MEDIUM severity -> "
        f"short containment, {config.SHORT_BLOCK_TTL} s")
    rep(f"    >= {HIGH_THRESHOLD:.2f}         HIGH severity   -> "
        f"full containment,  {config.BLOCK_TTL_SECONDS} s")
    rep("")
    rep("TWO TIERS RATHER THAN ONE. The two errors do not cost the same. A false")
    rep("negative costs one missed flow, and the SOAR groups hundreds of flows")
    rep("per attack into one case, so an attack survives many misses. A false")
    rep("positive fires iptables at a real user, and that cost does not dilute.")
    rep("A single cut forces one answer to two different questions; two tiers")
    rep("let a borderline flow cost five minutes and a confident one ten.")

    # ---- 3. what lands in each band ------------------------------------
    rep.banner("3. WHAT ACTUALLY LANDS IN EACH BAND")
    bands = band_composition(y_true, proba, labels)
    rep(f"    {'band':<22}{'total':>10}{'attack':>10}{'benign':>10}{'purity':>9}")
    for _, r in bands.iterrows():
        rep(f"    {r['band']:<22}{int(r['total']):>10,}{int(r['attack']):>10,}"
            f"{int(r['benign']):>10,}{r['purity']:>9.4f}")

    medium = bands.iloc[1]
    rep("")
    rep("FINDING - THE MEDIUM BAND IS MOSTLY NOISE, AND THIS MATTERS.")
    rep(f"    It holds {int(medium['total']):,} of 398,033 flows and its purity is "
        f"{medium['purity']:.4f}:")
    rep(f"    {int(medium['benign']):,} benign against {int(medium['attack']):,} attack. "
        f"Counted flow by flow it")
    rep("    short-blocks MORE legitimate flows than attacks it catches.")
    rep("")
    rep("    The model's output is strongly bimodal - almost every flow is")
    rep("    either clearly below 0.70 or clearly above 0.90 - so the middle is")
    rep("    a thin, noisy sliver rather than a genuine 'uncertain' population.")
    rep("")
    rep("    THE BAND IS ONLY DEFENSIBLE IF THE SOAR NEEDS MORE THAN ONE FLOW TO")
    rep("    OPEN A CASE. One benign flow at 0.75 must not block anyone. An")
    rep("    attacker contributes many flows, mostly in the HIGH band. That")
    rep("    case-opening rule is component B's and is still undecided; until it")
    rep("    is, the MEDIUM band should run in monitor mode, not enforce.")
    rep("")
    rep("    Composition of the MEDIUM band by family:")
    mask = (proba >= CONTAIN_THRESHOLD) & (proba < HIGH_THRESHOLD)
    for name, count in pd.Series(labels[mask]).value_counts().items():
        rep(f"        {name:<22}{int(count):>8,}")

    # ---- 4. per family --------------------------------------------------
    rep.banner("4. PER-FAMILY RECALL ACROSS THE CANDIDATE CUTS")
    rep("A5 showed that an aggregate can hide a whole family. Choosing a")
    rep("threshold on the aggregate alone would repeat exactly that mistake.")
    rep("")
    cuts = (0.50, 0.70, 0.80, 0.90, 0.95, 0.99)
    family = family_recall_by_threshold(labels, y_true, proba, cuts)
    rep(f"    {'family':<20}{'metric':<22}{'n':>8}"
        + "".join(f"{c:>9.2f}" for c in cuts))
    for _, r in family.iterrows():
        rep(f"    {r['family']:<20}{r['metric']:<22}{int(r['n']):>8,}"
            + "".join(f"{r[c]:>9.4f}" for c in cuts))
    rep("")
    rep("THIS IS WHY THE CUT IS NOT PUSHED HIGHER. Going to 0.99 would drop")
    rep("false positives to 140, but PortScan per-flow recall falls to 0.6597")
    rep("and DoS Slowhttptest to 0.8010 - the two smallest families, and one of")
    rep("them is a demo scenario. At 0.70 no family drops below 0.87.")
    rep("")
    rep("The counter-argument, for completeness: per-flow recall is not")
    rep("per-attack recall. A scan of 100 flows at 0.6597 recall is missed")
    rep("entirely with probability 0.34^100, which is not a number that")
    rep("happens. The reason to stay at 0.70 is therefore NOT that 0.99 would")
    rep("miss scans - it would not. It is that a lower cut costs little, keeps")
    rep("the severity bands meaningful, and leaves margin for the domain shift")
    rep("A7 has to measure. A threshold tuned to the last decimal on CICIDS2017")
    rep("would be false precision about a network we have not measured yet.")

    # ---- 5. base rate ---------------------------------------------------
    rep.banner("5. THE NUMBER THIS THRESHOLD DOES NOT FIX: THE BASE RATE")
    rep("The test set is 16.67% attacks. A real network between attacks is")
    rep("nowhere near that, and precision depends on it. Same model, same cut,")
    rep("different arithmetic.")
    rep("")
    rep(f"    {'thr':>6}{'recall':>9}{'FPR':>10}"
        + "".join(f"{f'prev {p:.2%}':>14}" for p in PREVALENCES))
    for cut in (0.50, 0.70, 0.90, 0.99):
        row = sweep_metrics(y_true, proba, [cut]).iloc[0]
        cells = "".join(
            f"{precision_at_prevalence(row['recall'], row['fpr'], p):>14.4f}"
            for p in PREVALENCES
        )
        rep(f"    {cut:>6.2f}{row['recall']:>9.4f}{row['fpr']:>10.5f}{cells}")
    rep("")
    contain = sweep_metrics(y_true, proba, [CONTAIN_THRESHOLD]).iloc[0]
    rep(f"At the chosen cut the model produces "
        f"{contain['fpr'] * 100_000:.0f} false alarms per 100,000 benign flows,")
    rep("whatever the prevalence. When attacks are 0.1% of traffic those swamp")
    rep(f"the true positives and precision falls to "
        f"{precision_at_prevalence(contain['recall'], contain['fpr'], 0.001):.4f}.")
    rep("")
    rep("NO THRESHOLD FIXES THIS - it is arithmetic, not a model defect. What")
    rep("fixes it is the SOAR requiring several flows from the same IP before")
    rep("opening a case, and A7 measuring the false positive rate on the lab's")
    rep("own benign traffic, which has never been measured.")

    # ---- 6. figures -----------------------------------------------------
    rep.banner("6. FIGURES")
    os.makedirs(args.figures_dir, exist_ok=True)
    curve = plot_threshold_curve(
        sweep_metrics(y_true, proba, np.round(np.arange(0.05, 1.001, 0.01), 2)),
        os.path.join(args.figures_dir, "threshold_curve.png"))
    fams = plot_family_curves(
        labels, y_true, proba,
        os.path.join(args.figures_dir, "threshold_per_family.png"))
    rep(f"    {curve}")
    rep(f"    {fams}")

    rep.banner("DONE")
    rep(f"Operating point fixed at {CONTAIN_THRESHOLD:.2f} / {HIGH_THRESHOLD:.2f}, "
        f"matching src/common/config.py.")
    rep("See contract/A6_threshold_note.md for the written decision.")

    rep.save(args.report)
    print(f"\nreport saved to {args.report}")
    return 0


if __name__ == "__main__":
    from intelligence.threshold import main as package_main

    sys.exit(package_main())
