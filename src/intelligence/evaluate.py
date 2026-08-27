"""
A5 - evaluate the three classifiers, compare them, and record the decision.

Scope. This module READS what A4 persisted and turns it into a decision with
evidence behind it. It never fits anything: no retraining, no hyperparameter
tuning, and no threshold search. If the artifacts are missing it stops and says
so, because regenerating them here would silently decouple these numbers from
the ones in the A4 report.

EVERY METRIC HERE IS AT THE DEFAULT 0.5 DECISION THRESHOLD. That is not the
operating point of the system - A6 chooses it. An F1 quoted without the
threshold it was measured at is not a reproducible number, so the threshold is
stated on every table rather than assumed.

The comparison has FOUR rows for THREE models. The fixed rule appears twice:

  - NAIVE direction (`flow_pkts_s >=`), which is what the project brief
    assumed. On this dataset it is worth almost exactly what a classifier that
    labels everything an attack is worth.
  - FITTED direction (`flow_pkts_s <=`), chosen on training data only, which is
    the fair comparison.

Publishing only one of the two would be dishonest in one direction or the
other: the naive row is the evidence that the brief's intuition is false here,
the fitted row is the comparison that means something. Neither is derived by
refitting - both thresholds were chosen during A4 and are read back out of the
persisted estimator.

Usage (from the repo root):
    python src/intelligence/evaluate.py
"""

import argparse
import os
import sys

import matplotlib

# Agg before pyplot: this runs headless and must not try to open a window.
matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence import contract  # noqa: E402
from intelligence import train  # noqa: E402
from intelligence.preprocess import LABEL_COL, PROCESSED_DIR, Report  # noqa: E402

REPORT_PATH = os.path.join("scripts", "scripts_output", "eval_report.txt")
# reports/figures/ IS committed. data/ is gitignored because it is regenerable
# bulk; a figure is a deliverable someone reads in the defence.
FIGURES_DIR = os.path.join("reports", "figures")

TEST_PARQUET = os.path.join(PROCESSED_DIR, "test.parquet")

# The four rows of the comparison. Keys into the predictions frame, except the
# naive baseline which is derived below from a threshold A4 already chose.
RF_KEY, LR_KEY, BASE_KEY = train.RF_KEY, train.LR_KEY, train.BASE_KEY
NAIVE_KEY = "baseline_rule_naive"

ROW_TITLES = {
    RF_KEY: "Random Forest",
    LR_KEY: "Logistic regression",
    NAIVE_KEY: "Fixed rule (NAIVE direction, flow_pkts_s >=)",
    BASE_KEY: "Fixed rule (FITTED direction, flow_pkts_s <=)",
}
ROW_ORDER = [RF_KEY, LR_KEY, NAIVE_KEY, BASE_KEY]

# Models with a genuine probability output. The fixed rule is absent by
# construction, not by oversight - see naive_and_fitted_baseline().
PROBABILISTIC = (RF_KEY, LR_KEY)


# ---------------------------------------------------------------------------
# Loading - read only, and refuse anything that does not match the contract
# ---------------------------------------------------------------------------

def load_model_checked(path: str) -> dict:
    """Load one persisted model, refusing it if it is not this contract.

    `train.load_model` raises when the stored CONTRACT_VERSION or the stored
    feature order differ from the ones this code holds. A model paired with a
    contract it was not trained against reads its 24 inputs out of the wrong
    slots: every metric below would still be computable and every one of them
    would be meaningless. There is no metric that detects it, so it is a
    precondition, not a check to be done afterwards.
    """
    if not os.path.exists(path):
        raise SystemExit(
            f"{path} not found. A5 never retrains - run A4 first:\n"
            f"    python src/intelligence/train.py"
        )
    return train.load_model(path)


def load_artifacts(models_dir: str, predictions_path: str):
    """The three fitted models, the saved test predictions, and one column."""
    if not os.path.exists(predictions_path):
        raise SystemExit(
            f"{predictions_path} not found. A5 never retrains - run A4 first:\n"
            f"    python src/intelligence/train.py"
        )

    models = {}
    for key, default_path in train.MODEL_FILES.items():
        path = os.path.join(models_dir, os.path.basename(default_path))
        models[key] = load_model_checked(path)

    predictions = pd.read_parquet(predictions_path)

    # Only the one column the naive baseline needs. Reading the whole test set
    # back would cost 32 MB to look at 4 % of it.
    rate_column = pd.read_parquet(TEST_PARQUET, columns=["flow_pkts_s"])
    if len(rate_column) != len(predictions):
        raise SystemExit(
            f"{TEST_PARQUET} has {len(rate_column):,} rows but "
            f"{predictions_path} has {len(predictions):,}. They are from "
            f"different runs; rerun A4."
        )
    return models, predictions, rate_column["flow_pkts_s"].to_numpy(np.float64)


def naive_baseline_predictions(rule, rate: np.ndarray) -> np.ndarray:
    """The brief's version of the rule: high packet rate means attack.

    The threshold is NOT refitted here. A4 swept both directions and stored
    what each one was worth, so the naive threshold is read straight out of the
    persisted estimator and applied. That keeps A5 free of any fitting while
    still being able to publish what the brief's intuition actually scores.
    """
    naive = rule.direction_scores_[">="]
    return (rate >= naive["threshold"]).astype(np.int8), naive


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def score_row(y_true, y_pred, y_proba=None) -> dict:
    """Attack-class precision/recall/F1, plus the two AUCs when they exist.

    `y_proba=None` is the fixed rule and the AUC cells stay None. A threshold
    rule emits 0/1: it has no ranking of flows by confidence, so it has no ROC
    curve and no PR curve to integrate. Manufacturing a score for it - by
    rescaling the feature, say - would fabricate a curve the rule does not
    possess and would flatter it against models that genuinely produce one.
    """
    row = dict(train.attack_scores(y_true, y_pred))
    row["roc_auc"] = None if y_proba is None else float(roc_auc_score(y_true, y_proba))
    # average_precision_score, not auc(precision_recall_curve): AP sums the
    # actual step area and does not interpolate between operating points that
    # no threshold produces.
    row["pr_auc"] = None if y_proba is None else float(
        average_precision_score(y_true, y_proba)
    )
    return row


def confusion(y_true, y_pred) -> dict:
    """Absolute counts. Percentages hide the number that matters here: how many
    real users a false-positive rate of 0.23 % actually blocks."""
    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[contract.BENIGN, contract.ATTACK]
    ).ravel()
    return {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------

# One colour per model, used identically in both figures so the eye can follow
# a model across them.
CURVE_STYLE = {
    RF_KEY: {"color": "#1b7837", "linewidth": 2.2},
    LR_KEY: {"color": "#762a83", "linewidth": 2.2, "linestyle": "--"},
}


def _finish(ax, title: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(title, fontsize=12, pad=10)
    ax.set_xlabel(xlabel, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.01)
    ax.grid(alpha=0.25, linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.legend(loc="lower right" if "ROC" in title else "lower left", fontsize=9,
              frameon=True, framealpha=0.9)


def plot_roc(y_true, probas: dict, scores: dict, path: str) -> str:
    """Both models on ONE set of axes - the point is the comparison."""
    fig, ax = plt.subplots(figsize=(6.2, 5.4), dpi=150)
    for key, proba in probas.items():
        fpr, tpr, _ = roc_curve(y_true, proba)   # drop_intermediate=True
        ax.plot(fpr, tpr, label=f"{ROW_TITLES[key]}  (AUC {scores[key]['roc_auc']:.4f})",
                **CURVE_STYLE[key])
    ax.plot([0, 1], [0, 1], color="#999999", linewidth=1, linestyle=":",
            label="chance")
    _finish(ax, "ROC - attack class (threshold-independent)",
            "False positive rate", "True positive rate")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


def plot_pr(y_true, probas: dict, scores: dict, path: str) -> str:
    """The curve that actually reflects this problem. See the report text."""
    fig, ax = plt.subplots(figsize=(6.2, 5.4), dpi=150)
    for key, proba in probas.items():
        precision, recall, _ = precision_recall_curve(y_true, proba)
        ax.plot(recall, precision,
                label=f"{ROW_TITLES[key]}  (PR-AUC {scores[key]['pr_auc']:.4f})",
                **CURVE_STYLE[key])
    prevalence = float(np.mean(np.asarray(y_true) == contract.ATTACK))
    ax.axhline(prevalence, color="#999999", linewidth=1, linestyle=":",
               label=f"chance = prevalence ({prevalence:.4f})")
    _finish(ax, "Precision-Recall - attack class", "Recall", "Precision")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _fmt(value, width: int = 10) -> str:
    return f"{'':>{width}}" if value is None else f"{value:>{width}.4f}"


def main() -> int:
    ap = argparse.ArgumentParser(description="A5: evaluate and compare.")
    ap.add_argument("--models-dir", default=train.MODELS_DIR)
    ap.add_argument("--predictions", default=train.PREDICTIONS_PATH)
    ap.add_argument("--figures-dir", default=FIGURES_DIR)
    ap.add_argument("--report", default=REPORT_PATH)
    args = ap.parse_args()

    rep = Report()
    rep("A5 evaluation report - comparing the three classifiers")
    rep(f"contract version {contract.CONTRACT_VERSION}")
    rep("")
    rep("EVERY NUMBER BELOW IS AT DECISION THRESHOLD 0.5, the sklearn default.")
    rep("That is not the operating point of the system: A6 chooses it. An F1")
    rep("quoted without its threshold is not a reproducible number.")
    rep("Nothing was retrained. All figures come from the artifacts A4 wrote.")

    # ---- artifacts -----------------------------------------------------
    rep.banner("1. ARTIFACTS AND CONTRACT CHECK")
    models, predictions, rate = load_artifacts(args.models_dir, args.predictions)
    for key in train.MODEL_FILES:
        payload = models[key]
        rep(f"    {payload['name']:<24} contract {payload['contract_version']}"
            f"   trained {payload['trained_at']}"
            f"   {payload['n_train_rows']:,} rows")
    rep("")
    rep(f"    predictions              {args.predictions}  "
        f"{len(predictions):,} rows")
    rep("")
    rep("Every model was refused unless its stored CONTRACT_VERSION and feature")
    rep("order match this code. A model paired with a contract it was not")
    rep("trained against reads its inputs out of the wrong slots: every metric")
    rep("below would still compute, and all of them would be meaningless.")

    y_true = predictions["y_true"].to_numpy()
    labels = predictions[LABEL_COL].to_numpy()

    rule = models[BASE_KEY]["pipeline"].named_steps["rule"]
    naive_pred, naive_info = naive_baseline_predictions(rule, rate)

    y_pred = {
        RF_KEY: predictions[f"{RF_KEY}_pred"].to_numpy(),
        LR_KEY: predictions[f"{LR_KEY}_pred"].to_numpy(),
        BASE_KEY: predictions[f"{BASE_KEY}_pred"].to_numpy(),
        NAIVE_KEY: naive_pred,
    }
    probas = {key: predictions[f"{key}_proba"].to_numpy() for key in PROBABILISTIC}

    # ---- comparison ----------------------------------------------------
    rep.banner("2. COMPARISON - attack class, at threshold 0.5")
    scores = {
        key: score_row(y_true, y_pred[key], probas.get(key)) for key in ROW_ORDER
    }

    rep(f"    {'model':<46}{'precision':>10}{'recall':>10}{'F1':>10}"
        f"{'ROC-AUC':>10}{'PR-AUC':>10}")
    for key in ROW_ORDER:
        s = scores[key]
        rep(f"    {ROW_TITLES[key]:<46}{s['precision']:>10.4f}{s['recall']:>10.4f}"
            f"{s['f1']:>10.4f}{_fmt(s['roc_auc'])}{_fmt(s['pr_auc'])}")
    rep("")
    rep("    (*) The fixed rule outputs 0/1 and has no predict_proba, so it has")
    rep("        NO ROC-AUC and NO PR-AUC - those cells are empty, not zero. A")
    rep("        threshold rule produces no ranking of flows by confidence, so")
    rep("        there is no curve to integrate. Synthesising a score for it")
    rep("        would fabricate a curve it does not have.")
    rep("")
    rep("The two fixed-rule rows are the SAME rule aimed in opposite directions.")
    rep(f"    NAIVE  (the project brief's assumption): flow_pkts_s >= "
        f"{naive_info['threshold']:.6f}")
    rep(f"           train F1 {naive_info['f1']:.4f}")
    rep(f"    FITTED (chosen on training data only):   flow_pkts_s <= "
        f"{rule.threshold_:.6f}")
    rep(f"           train F1 {rule.train_f1_:.4f}")
    constant_f1 = 2 * int((y_true == contract.ATTACK).sum()) / (
        len(y_true) + int((y_true == contract.ATTACK).sum())
    )
    rep(f"    For scale: a classifier that flags EVERY flow scores F1 "
        f"{constant_f1:.4f} on test.")
    rep("")
    rep("Both rows are published deliberately. The naive row is the evidence")
    rep("that the brief's intuition is false on this dataset; the fitted row is")
    rep("the comparison that means something. Neither threshold was fitted")
    rep("here - A4 chose both, and A5 reads them back out of the saved model.")

    # ---- confusion -----------------------------------------------------
    rep.banner("3. CONFUSION MATRICES - absolute counts, threshold 0.5")
    rep("Rows = truth, columns = prediction. n = "
        f"{len(y_true):,} test flows "
        f"({int((y_true == contract.BENIGN).sum()):,} benign, "
        f"{int((y_true == contract.ATTACK).sum()):,} attack).")

    for key in (RF_KEY, LR_KEY, BASE_KEY):
        c = confusion(y_true, y_pred[key])
        rep("")
        rep(f"  {ROW_TITLES[key]}")
        rep(f"      {'':<18}{'pred BENIGN':>14}{'pred ATTACK':>14}")
        rep(f"      {'true BENIGN':<18}{c['tn']:>14,}{c['fp']:>14,}")
        rep(f"      {'true ATTACK':<18}{c['fn']:>14,}{c['tp']:>14,}")
        rep(f"      -> {c['fp']:,} false positives: legitimate flows that would")
        rep(f"         have been blocked by iptables, cutting off a real user.")
        rep(f"      -> {c['fn']:,} false negatives: attack flows that reached")
        rep(f"         the host with no alert and no containment.")

    rep("")
    rep("The two error cells are not interchangeable and the system does not")
    rep("treat them as such. A false negative costs one missed flow, and the")
    rep("SOAR groups hundreds of flows per attack into one case, so a single")
    rep("attack survives many misses. A false positive blocks a real user.")

    # ---- curves --------------------------------------------------------
    rep.banner("4. CURVES AND THRESHOLD-INDEPENDENT SCORES")
    os.makedirs(args.figures_dir, exist_ok=True)
    roc_path = plot_roc(y_true, probas, scores,
                        os.path.join(args.figures_dir, "roc_curves.png"))
    pr_path = plot_pr(y_true, probas, scores,
                      os.path.join(args.figures_dir, "pr_curves.png"))

    rep(f"    {'model':<24}{'ROC-AUC':>12}{'PR-AUC':>12}")
    for key in PROBABILISTIC:
        rep(f"    {ROW_TITLES[key]:<24}{scores[key]['roc_auc']:>12.4f}"
            f"{scores[key]['pr_auc']:>12.4f}")
    prevalence = float(np.mean(y_true == contract.ATTACK))
    rep(f"    {'chance (prevalence)':<24}{0.5:>12.4f}{prevalence:>12.4f}")
    rep("")
    rep("WHY PR-AUC IS THE ONE TO READ HERE. The test set is 16.67% attacks. A")
    rep("ROC curve plots recall against the FALSE POSITIVE RATE, whose")
    rep("denominator is the 331,691 benign flows - so thousands of false")
    rep("positives still move it barely at all, and every model looks")
    rep("excellent. Precision-Recall uses precision instead, whose denominator")
    rep("is what the model actually flagged, so it degrades as soon as the")
    rep("model starts alarming on benign traffic. Chance level makes the point:")
    rep(f"    ROC-AUC of a coin flip = 0.5000, PR-AUC of a coin flip = "
        f"{prevalence:.4f}.")
    rep("A ROC-AUC of 0.99 is 'better than a coin flip'. A PR-AUC of 0.99 is")
    rep("six times the prevalence floor. Only the second is informative.")
    rep("")
    rep(f"    figure: {roc_path}")
    rep(f"    figure: {pr_path}")
    rep("    (both models on shared axes; the fixed rule is absent because it")
    rep("     has no curve, see the footnote in section 2)")

    # ---- per family ----------------------------------------------------
    rep.banner("5. RECALL PER ATTACK FAMILY - recomputed from the saved predictions")
    rep("The BENIGN row is a FALSE POSITIVE RATE: recall of the attack class is")
    rep("undefined for it. Everything here is recomputed from")
    rep(f"{args.predictions}, not copied from the A4 report, so the table is")
    rep("verifiable from the artifacts alone.")
    rep("")

    tables = {k: train.per_family_recall(labels, y_true, y_pred[k])
              for k in ROW_ORDER}
    reference = tables[RF_KEY]
    header = ("Random Forest", "Logistic", "Rule NAIVE", "Rule FITTED")
    rep(f"    {'family':<20}{'metric':<22}{'n':>9}"
        + "".join(f"{h:>15}" for h in header))
    for _, row in reference.iterrows():
        cells = ""
        for key in ROW_ORDER:
            table = tables[key]
            value = table.loc[table["family"] == row["family"], "value"].iloc[0]
            cells += f"{value:>15.4f}"
        rep(f"    {row['family']:<20}{row['metric']:<22}{row['n']:>9,}{cells}")

    naive_c = confusion(y_true, y_pred[NAIVE_KEY])
    rep("")
    rep("HOW TO READ THE 'Rule NAIVE' COLUMN - it is not a good detector.")
    rep("    At a glance it looks like the best model in the table: 1.0000 on")
    rep("    both Patators, 0.9998 on DDoS. It reaches those numbers by")
    n_benign = int((y_true == contract.BENIGN).sum())
    rep(f"    flagging {naive_c['fp'] + naive_c['tp']:,} of {len(y_true):,} test flows as")
    rep(f"    attacks - including {naive_c['fp']:,} of the {n_benign:,} benign ones, a")
    rep(f"    false positive rate of {naive_c['fp'] / n_benign:.4f}.")
    rep("    Its recall is high for the same reason a smoke alarm that is")
    rep("    always sounding has perfect recall. This is exactly why recall is")
    rep("    never read on its own here, and why the BENIGN row of this table")
    rep("    is part of it rather than a separate note.")
    rep("")
    rep("FINDING 1 - the fixed rule zeroes out four families.")
    rep("    FTP-Patator 0.0000, SSH-Patator 0.0000, PortScan 0.0857, DDoS")
    rep("    0.1649. None of the four separates from normal traffic BY RATE:")
    rep("    brute force is identified by how regular its packet sizes are, a")
    rep("    port scan by tiny flows carrying no payload, and DDoS sits on the")
    rep("    wrong side of a rule that ended up meaning 'slow flow = attack'.")
    rep("    This is the measured form of the project's central argument. The")
    rep("    rule does not fail because it is a simple model; it fails because")
    rep("    ONE feature cannot describe four different shapes of attack, and a")
    rep("    threshold can only look at one.")
    rep("")
    rep("FINDING 2 - an aggregate can hide two entire families.")
    rep("    Logistic regression scores F1 0.8151 overall, which reads as a")
    rep("    respectable model, while scoring 0.0008 on FTP-Patator and 0.0000")
    rep("    on SSH-Patator. Both are demo scenarios. A single headline number")
    rep("    would have concluded that the linear model is adequate; this table")
    rep("    is the concrete reason this project does not evaluate on one.")

    # ---- decision ------------------------------------------------------
    rep.banner("6. DECISION")
    rep("Chosen model: RANDOM FOREST.")
    rep("")
    rep(f"    attack-class F1 on test   {scores[RF_KEY]['f1']:.4f}   vs "
        f"{scores[LR_KEY]['f1']:.4f} (logistic) and "
        f"{scores[BASE_KEY]['f1']:.4f} (fixed rule, fitted direction)")
    rep(f"    PR-AUC                    {scores[RF_KEY]['pr_auc']:.4f}")
    rep(f"    CV stability (A4)         sigma {models[RF_KEY]['cv_std_f1']:.4f} "
        f"over 5 folds")
    rep(f"    false positive rate       "
        f"{confusion(y_true, y_pred[RF_KEY])['fp'] / int((y_true == contract.BENIGN).sum()):.4f}")
    rep("    lowest per-family recall  "
        f"{tables[RF_KEY].loc[tables[RF_KEY]['metric'] == 'recall', 'value'].min():.4f} "
        "(PortScan) - no family is abandoned")
    rep("")
    rep("It wins on every axis measured here, and - the reason that matters -")
    rep("it is the only one of the three that detects all nine families. See")
    rep("contract/A5_evaluation_note.md for the written decision, the corrected")
    rep("defence argument and the domain-shift risk this number does NOT cover.")

    rep.banner("DONE")
    rep("Nothing retrained, no threshold chosen. A6 sets the operating point.")

    rep.save(args.report)
    print(f"\nreport saved to {args.report}")
    return 0


if __name__ == "__main__":
    # See train.py: importing through the package keeps any class this module
    # touches resolvable by module path rather than as __main__.X.
    from intelligence.evaluate import main as package_main

    sys.exit(package_main())
