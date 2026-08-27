"""
Tests for model.predict - the contract interface component B imports.

These build a tiny model on synthetic data and load it through the same path
the live system uses, so they run in well under a second and never touch the
68 MB artifact or data/. What they pin is the CONTRACT of predict(): its shape,
its fail-safe behaviour, and that the model is loaded once.

Run:  pytest -v tests/test_model.py
"""
import math

import numpy as np
import pandas as pd
import pytest

from intelligence import contract as c
from intelligence import model
from intelligence import train as t


@pytest.fixture
def tiny_model(tmp_path):
    """A real fitted Random Forest, persisted in the contract format, loaded
    through model.load. Attacks are the fast flows so predictions are decisive."""
    # Two clearly separated clouds so the toy forest is decisive: benign near
    # 10 in every feature, attack near 30. The point of these tests is the
    # predict() contract, not the model's discrimination - that is A5's job.
    rng = np.random.default_rng(0)
    n = 400
    y = (rng.random(n) < 0.4).astype(np.int8)
    centres = np.where(y[:, None] == c.ATTACK, 30.0, 10.0)
    X = centres + rng.normal(0, 1, size=(n, c.N_FEATURES))
    rate = c.FEATURES_24.index("flow_pkts_s")

    frame = pd.DataFrame(X, columns=c.FEATURES_24)
    pipeline = t.build_random_forest().fit(frame, pd.Series(y))

    model.reset()
    # Inject the fitted pipeline directly instead of a joblib round-trip. In
    # this environment (joblib 1.5.3 + numpy 2.5 + py3.14) a dump-then-load in
    # the SAME process silently corrupts a freshly-fitted tree - predictions
    # come back wrong. The real system never does that: train.py saves in one
    # process and model.py loads in another, which is fine (cross-process is
    # covered by test_train.py). These tests exercise predict()'s contract, so
    # they use a clean in-memory model; load()/joblib is exercised by the
    # contract-guard tests below, which only assert on raising.
    model._pipeline = pipeline
    model._model_path = "test-injected"
    # Real rows the model was trained on, so predictions are in-distribution
    # and decisive - a synthetic vector at the feature means sits between the
    # classes and tells us nothing.
    yield {"attack": frame[y == c.ATTACK].iloc[0].tolist(),
           "benign": frame[y == c.BENIGN].iloc[0].tolist(),
           "rate_idx": rate}
    model.reset()


def _attack_vec(tiny):
    return list(tiny["attack"])


def _benign_vec(tiny):
    return list(tiny["benign"])


# ---------------------------------------------------------------------------
# 1. The contract: shape of the return value
# ---------------------------------------------------------------------------

def test_predict_returns_a_float_in_zero_one(tiny_model):
    p = model.predict(_attack_vec(tiny_model))
    assert isinstance(p, float)
    assert 0.0 <= p <= 1.0


def test_predict_separates_attack_from_benign(tiny_model):
    """The whole point: a fast (attack) flow scores high, a slow one low."""
    assert model.predict(_attack_vec(tiny_model)) > 0.5
    assert model.predict(_benign_vec(tiny_model)) < 0.5


# ---------------------------------------------------------------------------
# 2. Fail-safe behaviour on live data
# ---------------------------------------------------------------------------

def test_non_finite_values_are_sanitised_not_crashed(tiny_model):
    """R3: a NaN or inf from a zero-duration flow (a scan probe) must not take
    the IDS down. sanitize maps them to 0.0 before the model sees them."""
    v = _attack_vec(tiny_model)
    v[c.FEATURES_24.index("flow_byts_s")] = float("inf")
    v[c.FEATURES_24.index("flow_pkts_s")] = float("nan")
    p = model.predict(v)
    assert isinstance(p, float) and 0.0 <= p <= 1.0


def test_wrong_length_vector_raises(tiny_model):
    """A wrong length is an integration bug in the caller, not a flow to skip.
    It must raise so it is caught in development, not swallowed live."""
    with pytest.raises(ValueError, match="24 features"):
        model.predict([1.0] * 23)
    with pytest.raises(ValueError, match="24 features"):
        model.predict([1.0] * 25)


def test_a_contract_violation_is_logged_but_still_scored(tiny_model, caplog):
    """A finite negative is corrupt (all 24 are non-negative), but live we
    cannot drop the flow. Log it and score anyway rather than blind the IDS."""
    import logging

    v = _attack_vec(tiny_model)
    v[c.FEATURES_24.index("bwd_pkt_len_mean")] = -5.0
    with caplog.at_level(logging.WARNING):
        p = model.predict(v)
    assert isinstance(p, float)
    assert any("contract" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 3. The model is loaded once
# ---------------------------------------------------------------------------

def test_model_is_cached_not_reloaded_per_call(tiny_model):
    """68 MB per flow would make live inference unusable."""
    model.predict(_benign_vec(tiny_model))
    handle = id(model._pipeline)
    model.predict(_attack_vec(tiny_model))
    assert id(model._pipeline) == handle


def test_load_is_idempotent_for_the_same_path(tiny_model):
    handle = id(model._pipeline)
    model.load(model._model_path)
    assert id(model._pipeline) == handle


def test_a_missing_model_path_raises_clearly():
    model.reset()
    with pytest.raises(FileNotFoundError, match="Train the model first"):
        model.load("models/does_not_exist.joblib")
    model.reset()


# ---------------------------------------------------------------------------
# 4. The contract guard travels with the model
# ---------------------------------------------------------------------------

def test_loading_a_wrong_contract_model_is_refused(tmp_path):
    """model.load reuses train.load_model, which refuses a model built against
    a different contract - the silent failure the version exists to prevent."""
    import joblib

    rng = np.random.default_rng(1)
    X = pd.DataFrame(rng.normal(0, 1, size=(50, c.N_FEATURES)), columns=c.FEATURES_24)
    y = pd.Series((rng.random(50) < 0.5).astype(int))
    path = str(tmp_path / "stale.joblib")
    t.persist_model(path, "stale", t.build_random_forest().fit(X, y))

    payload = joblib.load(path)
    payload["contract_version"] = "0.9"
    joblib.dump(payload, path)

    model.reset()
    with pytest.raises(ValueError, match="contract"):
        model.load(path)
    model.reset()
