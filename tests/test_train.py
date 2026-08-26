"""
Tests for the A4 training module.

None of these touch data/. They run on synthetic frames of a few hundred rows,
so the file finishes in about a second and can be run on every save. Fitting
the real models takes minutes; that is what the report is for.

Each test corresponds to one way A4 could be wrong while looking right:

  - the baseline calibrating its threshold on data it is then scored on, which
    would make the whole A5 comparison meaningless in our favour;
  - the scaler sitting outside the logistic Pipeline, the serialisation failure
    the project documents as critical;
  - a scaler wired into the forest, which would cost a pass over 1.6M rows to
    change nothing;
  - columns arriving permuted, the one error no metric can reveal;
  - a result that does not reproduce, which would make every quoted number a
    one-off.

Run:  pytest -v tests/test_train.py
"""
import sys

import numpy as np
import pandas as pd
import pytest
from sklearn.preprocessing import StandardScaler

from intelligence import contract as c
from intelligence import train as t


def _frame(values: np.ndarray) -> pd.DataFrame:
    return pd.DataFrame(values, columns=c.FEATURES_24)


def _separable(n: int = 400, seed: int = 0):
    """A tiny problem the rule can actually solve: attacks are the fast flows.

    Built so that `flow_pkts_s` alone separates the classes, because that is
    the feature the baseline is allowed to look at.
    """
    rng = np.random.default_rng(seed)
    X = rng.normal(10, 1, size=(n, c.N_FEATURES))
    y = np.zeros(n, dtype=np.int8)

    rate = c.FEATURES_24.index("flow_pkts_s")
    attack = rng.random(n) < 0.3
    y[attack] = c.ATTACK
    X[:, rate] = np.where(attack, rng.normal(500, 20, n), rng.normal(5, 1, n))

    return _frame(X), pd.Series(y)


# ---------------------------------------------------------------------------
# 1. The fixed-rule baseline
# ---------------------------------------------------------------------------

def test_baseline_fits_and_predicts_on_a_tiny_frame():
    X, y = _separable()
    rule = t.FixedRuleBaseline().fit(X, y)

    predicted = rule.predict(X)
    assert predicted.shape == (len(X),)
    assert set(np.unique(predicted)) <= {c.BENIGN, c.ATTACK}
    # The problem is separable by construction; a rule that cannot solve it
    # would mean the sweep, not the data, is broken.
    assert rule.train_f1_ > 0.95


def test_baseline_threshold_lands_between_the_two_populations():
    X, y = _separable()
    rule = t.FixedRuleBaseline().fit(X, y)
    rate = X["flow_pkts_s"]
    assert rate[y == c.BENIGN].max() < rule.threshold_ <= rate[y == c.ATTACK].max()


def test_baseline_threshold_comes_from_training_data_alone():
    """Calibrating on test would hand the baseline an advantage the other two
    models are not given, and A5's comparison would be worthless."""
    X_train, y_train = _separable(seed=0)
    rule = t.FixedRuleBaseline().fit(X_train, y_train)
    chosen = rule.threshold_

    # Refitting on a differently-scaled test set must not move the threshold:
    # `fit` is the only thing that may set it, and `predict` never looks at y.
    X_test, y_test = _separable(seed=1)
    X_test["flow_pkts_s"] *= 1000
    rule.predict(X_test)
    assert rule.threshold_ == chosen

    # And the chosen value must be reachable from the training values only.
    assert X_train["flow_pkts_s"].min() <= chosen <= X_train["flow_pkts_s"].max()


def test_baseline_fits_its_direction_from_the_data():
    """The operational rule says 'high rate = attack'. On the real dataset that
    direction scores what a constant classifier scores, because the attacks are
    the SLOW flows. So the direction is fitted, not assumed - and it must be
    able to come out either way."""
    X_fast, y_fast = _separable()                 # attacks are the fast flows
    assert t.FixedRuleBaseline().fit(X_fast, y_fast).direction_ == ">="

    X_slow, y_slow = _separable()                 # mirror it: attacks are slow
    X_slow["flow_pkts_s"] = -X_slow["flow_pkts_s"]
    assert t.FixedRuleBaseline().fit(X_slow, y_slow).direction_ == "<="


def test_baseline_direction_is_chosen_on_training_f1_alone():
    """Both directions are swept and the better TRAINING score wins; the losing
    direction is kept only so the report can quote what it was worth."""
    X, y = _separable()
    rule = t.FixedRuleBaseline().fit(X, y)

    assert set(rule.direction_scores_) == {">=", "<="}
    kept = rule.direction_scores_[rule.direction_]["f1"]
    other = rule.direction_scores_["<=" if rule.direction_ == ">=" else ">="]["f1"]
    assert kept >= other
    assert rule.train_f1_ == pytest.approx(kept)


def test_baseline_predict_respects_the_fitted_direction():
    """A '<=' rule that predicted with '>=' would invert every label while
    still producing a plausible-looking confusion matrix."""
    X, y = _separable()
    X["flow_pkts_s"] = -X["flow_pkts_s"]
    rule = t.FixedRuleBaseline().fit(X, y)

    assert rule.direction_ == "<="
    expected = (X["flow_pkts_s"] <= rule.threshold_).to_numpy().astype(np.int8)
    assert np.array_equal(rule.predict(X), expected)


def test_baseline_has_no_predict_proba():
    """A threshold rule has no notion of confidence, so it has no ROC curve.
    Inventing one would flatter it against models that genuinely have one."""
    assert not hasattr(t.FixedRuleBaseline(), "predict_proba")
    assert not hasattr(t.build_baseline().fit(*_separable()), "predict_proba")


def test_baseline_reads_only_its_one_feature():
    """Changing any other column must not change a single prediction."""
    X, y = _separable()
    rule = t.FixedRuleBaseline().fit(X, y)
    before = rule.predict(X)

    noisy = X.copy()
    for column in c.FEATURES_24:
        if column != "flow_pkts_s":
            noisy[column] = noisy[column] * 1e6 + 17

    assert np.array_equal(rule.predict(noisy), before)


def test_baseline_works_on_a_raw_array_in_contract_order():
    """It falls back to position 21, which is why the order assertion exists."""
    X, y = _separable()
    rule = t.FixedRuleBaseline().fit(X, y)
    assert np.array_equal(rule.predict(X.to_numpy()), rule.predict(X))


# ---------------------------------------------------------------------------
# 2. Pipeline composition
# ---------------------------------------------------------------------------

def test_logistic_pipeline_contains_the_scaler():
    """Outside the Pipeline, joblib.dump saves the coefficients and not the
    scaler: the model then predicts confidently on unscaled live vectors."""
    steps = dict(t.build_logistic_regression().named_steps)
    assert isinstance(steps["scaler"], StandardScaler)
    # Order matters: scaling after the classifier would scale nothing.
    assert list(steps) == ["scaler", "logistic"]


def test_forest_pipeline_has_no_scaler():
    """Trees split on order, not magnitude: a scaler would cost a full pass
    over 1.6M rows to produce the identical tree."""
    steps = t.build_random_forest().named_steps
    assert not any(isinstance(s, StandardScaler) for s in steps.values())


def test_forest_and_logistic_carry_the_decided_imbalance_treatment():
    """A1 decided class_weight='balanced'; A3 deliberately left X_train alone
    so that the decision would land here and nowhere else."""
    assert t.build_random_forest().named_steps["forest"].class_weight == "balanced"
    assert t.build_logistic_regression().named_steps["logistic"].class_weight == "balanced"


# ---------------------------------------------------------------------------
# 3. The column-order assertion
# ---------------------------------------------------------------------------

def test_contract_order_accepts_the_contract_order():
    X, _ = _separable()
    t.assert_contract_order(X)


def test_contract_order_fires_when_columns_are_permuted():
    """A permuted frame trains a model that reads flow_duration out of the slot
    holding tot_fwd_pkts. Every metric would still look plausible."""
    X, _ = _separable()
    swapped = X[[c.FEATURES_24[1], c.FEATURES_24[0]] + list(c.FEATURES_24[2:])]

    with pytest.raises(AssertionError, match="contract order"):
        t.assert_contract_order(swapped)


def test_contract_order_fires_on_a_missing_or_extra_column():
    X, _ = _separable()
    with pytest.raises(AssertionError):
        t.assert_contract_order(X.drop(columns=[c.FEATURES_24[-1]]))
    with pytest.raises(AssertionError):
        t.assert_contract_order(X.assign(extra=1.0))


# ---------------------------------------------------------------------------
# 4. Reproducibility
# ---------------------------------------------------------------------------

def test_all_three_models_reproduce_across_two_runs():
    """Same seed, same data, same predictions. Without this every number in the
    report is a one-off that cannot be checked."""
    X, y = _separable()
    for build in (t.build_random_forest, t.build_logistic_regression, t.build_baseline):
        first = build().fit(X, y).predict(X)
        second = build().fit(X, y).predict(X)
        assert np.array_equal(first, second), build.__name__


def test_cross_validation_returns_one_score_per_fold():
    X, y = _separable()
    scores = t.cross_validate_f1(t.build_baseline(), X, y)
    assert scores.shape == (t.CV_FOLDS,)
    assert ((0.0 <= scores) & (scores <= 1.0)).all()


# ---------------------------------------------------------------------------
# 5. Measurement helpers
# ---------------------------------------------------------------------------

def test_per_family_recall_separates_recall_from_false_positive_rate():
    """Recall is undefined for BENIGN in an attack-class framing, so that row
    must report the false positive rate instead of a meaningless recall."""
    labels = ["BENIGN", "BENIGN", "PortScan", "PortScan"]
    y_true = [c.BENIGN, c.BENIGN, c.ATTACK, c.ATTACK]
    y_pred = [c.BENIGN, c.ATTACK, c.ATTACK, c.BENIGN]

    table = t.per_family_recall(labels, y_true, y_pred).set_index("family")

    assert table.loc["PortScan", "metric"] == "recall"
    assert table.loc["PortScan", "value"] == pytest.approx(0.5)
    assert table.loc["BENIGN", "metric"] == "false positive rate"
    assert table.loc["BENIGN", "value"] == pytest.approx(0.5)


def test_attack_scores_ignore_the_benign_class():
    """The benign class is the easy 83%; scoring it would flatter everything."""
    y_true = [c.BENIGN] * 8 + [c.ATTACK] * 2
    perfect_on_attack = [c.BENIGN] * 8 + [c.ATTACK] * 2
    assert t.attack_scores(y_true, perfect_on_attack)["f1"] == pytest.approx(1.0)

    misses_every_attack = [c.BENIGN] * 10
    assert t.attack_scores(y_true, misses_every_attack)["f1"] == 0.0


# ---------------------------------------------------------------------------
# 6. Persistence carries the contract
# ---------------------------------------------------------------------------

def test_persisted_model_carries_the_contract_version(tmp_path):
    X, y = _separable()
    path = str(tmp_path / "baseline.joblib")
    t.persist_model(path, "Fixed-rule baseline", t.build_baseline().fit(X, y))

    payload = t.load_model(path)
    assert payload["contract_version"] == c.CONTRACT_VERSION
    assert payload["features"] == list(c.FEATURES_24)
    assert np.array_equal(payload["pipeline"].predict(X),
                          t.build_baseline().fit(X, y).predict(X))


def test_baseline_class_is_importable_by_package_path():
    """pickle stores a class by module path. If FixedRuleBaseline were defined
    in the __main__ script, models/ would hold `__main__.FixedRuleBaseline` and
    no other process could load the baseline - an AttributeError at load time,
    in A5 and in the live IDS. It must resolve as a package attribute."""
    assert t.FixedRuleBaseline.__module__ == "intelligence.train"

    import importlib

    module = importlib.import_module(t.FixedRuleBaseline.__module__)
    assert getattr(module, t.FixedRuleBaseline.__qualname__) is t.FixedRuleBaseline


def test_persisted_baseline_survives_a_fresh_interpreter(tmp_path):
    """The round trip that actually failed: dump here, load in a process that
    never imported this test module."""
    import subprocess

    X, y = _separable()
    path = str(tmp_path / "baseline.joblib")
    t.persist_model(path, "Fixed-rule baseline", t.build_baseline().fit(X, y))

    code = (
        "import sys, joblib; sys.path.insert(0, 'src');"
        f"p = joblib.load({path!r});"
        "print(type(p['pipeline'].named_steps['rule']).__module__)"
    )
    result = subprocess.run([sys.executable, "-c", code],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "intelligence.train"


def test_loading_a_model_from_another_contract_is_refused(tmp_path):
    """A model paired with a contract it was not trained against is the silent
    failure the version exists to prevent."""
    import joblib

    X, y = _separable()
    path = str(tmp_path / "stale.joblib")
    t.persist_model(path, "stale", t.build_baseline().fit(X, y))

    payload = joblib.load(path)
    payload["contract_version"] = "0.9"
    joblib.dump(payload, path)

    with pytest.raises(ValueError, match="contract"):
        t.load_model(path)
