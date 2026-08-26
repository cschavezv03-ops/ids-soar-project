"""
Tests for the A5 evaluation module.

Light on purpose: A5 computes metrics from artifacts that A4 already verified,
so most of it is arithmetic that the report itself displays. These cover only
what could break SILENTLY - a wrong number that still looks like a number.

Run:  pytest -v tests/test_evaluate.py
"""
import numpy as np
import pandas as pd
import pytest

from intelligence import contract as c
from intelligence import evaluate as e
from intelligence import train as t


def _separable(n: int = 200, seed: int = 0):
    """Attacks are the fast flows, so the rule can fit both directions."""
    rng = np.random.default_rng(seed)
    X = rng.normal(10, 1, size=(n, c.N_FEATURES))
    y = np.zeros(n, dtype=np.int8)
    rate = c.FEATURES_24.index("flow_pkts_s")
    attack = rng.random(n) < 0.3
    y[attack] = c.ATTACK
    X[:, rate] = np.where(attack, rng.normal(500, 20, n), rng.normal(5, 1, n))
    return pd.DataFrame(X, columns=c.FEATURES_24), pd.Series(y)


# ---------------------------------------------------------------------------
# 1. No probability must ever be invented for the fixed rule
# ---------------------------------------------------------------------------

def test_score_row_leaves_the_auc_cells_empty_without_a_probability():
    """A threshold rule emits 0/1 and therefore has no curve to integrate.
    Synthesising a score would fabricate a curve it does not have, and would
    flatter it against the models that genuinely produce one."""
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 1, 1, 1])

    row = e.score_row(y_true, y_pred, y_proba=None)

    assert row["roc_auc"] is None
    assert row["pr_auc"] is None
    # The three it CAN have are still real numbers.
    assert row["recall"] == pytest.approx(1.0)
    assert row["precision"] == pytest.approx(2 / 3)


def test_score_row_computes_the_aucs_when_a_probability_exists():
    y_true = np.array([0, 0, 1, 1])
    proba = np.array([0.1, 0.2, 0.8, 0.9])
    row = e.score_row(y_true, (proba >= 0.5).astype(int), y_proba=proba)
    assert row["roc_auc"] == pytest.approx(1.0)
    assert row["pr_auc"] == pytest.approx(1.0)


def test_the_fitted_baseline_still_has_no_predict_proba():
    """The property score_row relies on. If a predict_proba ever appeared on
    the rule, the empty AUC cells would silently start filling in."""
    assert not hasattr(t.build_baseline().fit(*_separable()), "predict_proba")


def test_report_formatter_renders_a_missing_metric_as_blank_not_zero():
    """An empty cell means 'this model has no such metric'. A 0.0000 would read
    as 'this model scores zero', which is a different and false claim."""
    assert e._fmt(None).strip() == ""
    assert e._fmt(0.0).strip() == "0.0000"


# ---------------------------------------------------------------------------
# 2. The contract check
# ---------------------------------------------------------------------------

def test_contract_version_mismatch_is_refused(tmp_path):
    """A model paired with a contract it was not trained against reads its 24
    inputs out of the wrong slots. Every metric would still compute."""
    import joblib

    X, y = _separable()
    path = str(tmp_path / "stale.joblib")
    t.persist_model(path, "stale", t.build_baseline().fit(X, y))

    payload = joblib.load(path)
    payload["contract_version"] = "0.9"
    joblib.dump(payload, path)

    with pytest.raises(ValueError, match="contract"):
        e.load_model_checked(path)


def test_feature_order_mismatch_is_refused(tmp_path):
    import joblib

    X, y = _separable()
    path = str(tmp_path / "permuted.joblib")
    t.persist_model(path, "permuted", t.build_baseline().fit(X, y))

    payload = joblib.load(path)
    payload["features"] = list(reversed(c.FEATURES_24))
    joblib.dump(payload, path)

    with pytest.raises(ValueError, match="feature order"):
        e.load_model_checked(path)


def test_a_missing_model_stops_instead_of_retraining(tmp_path):
    """A5 must never regenerate what it evaluates: rebuilding here would
    decouple these numbers from the ones A4 published."""
    with pytest.raises(SystemExit, match="never retrains"):
        e.load_model_checked(str(tmp_path / "absent.joblib"))


# ---------------------------------------------------------------------------
# 3. The naive baseline row is read, not refitted
# ---------------------------------------------------------------------------

def test_naive_row_uses_the_threshold_a4_stored():
    """The naive direction is published as evidence that the brief's intuition
    is false. It must come out of the persisted estimator, not out of a fresh
    fit performed inside A5."""
    X, y = _separable()
    rule = t.build_baseline().fit(X, y).named_steps["rule"]
    rate = X["flow_pkts_s"].to_numpy()

    predicted, info = e.naive_baseline_predictions(rule, rate)

    assert info["threshold"] == rule.direction_scores_[">="]["threshold"]
    assert np.array_equal(predicted, (rate >= info["threshold"]).astype(np.int8))


# ---------------------------------------------------------------------------
# 4. Confusion cells must not be transposed
# ---------------------------------------------------------------------------

def test_confusion_cells_are_not_transposed():
    """fp and fn mean opposite things operationally - a blocked user versus an
    attack that reached the host - so swapping them inverts the conclusion."""
    y_true = np.array([c.BENIGN, c.BENIGN, c.BENIGN, c.ATTACK, c.ATTACK])
    y_pred = np.array([c.BENIGN, c.BENIGN, c.ATTACK, c.BENIGN, c.ATTACK])

    assert e.confusion(y_true, y_pred) == {"tn": 2, "fp": 1, "fn": 1, "tp": 1}
