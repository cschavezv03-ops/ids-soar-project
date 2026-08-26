"""
The inference interface the contract promises to component B.

Spec: contract/contract_characteristics.md section 2.

    def predict(feature_vector: list[float]) -> float

Frank calls this and nothing else. He hands it the 24-vector that
extract_features() produced and receives the probability that the flow is an
attack, between 0.0 and 1.0. Everything behind this function - which model,
which threshold, which contract version - is component A's concern and can
change without touching his code, as long as the signature holds.

WHAT THIS REPLACES. Until now src/system/pipeline.py wired a dummy_predictor
that returned 0.95 for every flow. That was a placeholder so the pipeline could
be built before the model existed. This module is the real thing: it loads the
Random Forest that A4 fitted, A5 chose and A7 calibrated, and scores a vector
through it. Frank swaps `dummy_predictor` for `from intelligence.model import
predict`.

TWO DELIBERATE DECISIONS, both defensible orally:

  1. The model is loaded ONCE and cached. It is 68 MB; reloading it per flow
     would make live inference unusable. load() can be called at start-up to
     pay that cost before traffic arrives; otherwise the first predict() pays
     it. The load refuses a model whose stored CONTRACT_VERSION or feature
     order does not match this code - a model paired with the wrong contract
     reads its 24 inputs out of the wrong slots and every score is wrong in a
     way no metric reveals.

  2. predict() FAILS SAFE on live data. A malformed flow must never take the
     IDS down (contract section on validate: "In the live pipeline prefer
     strict=False"). Non-finite values are mapped to 0.0 by R3 before the model
     sees them; a wrong-length vector is a caller bug and raises, because that
     is an integration error to catch early, not a flow to skip.
"""

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence import contract  # noqa: E402
from intelligence.train import MODEL_FILES, RF_KEY, load_model  # noqa: E402

log = logging.getLogger(__name__)

# The model chosen in A5. A path, not a loaded object, so importing this module
# is cheap - the 68 MB is only read when predict()/load() is first called.
DEFAULT_MODEL_PATH = MODEL_FILES[RF_KEY]

# Loaded once, cached here. None until the first load() or predict().
_pipeline = None
_model_path = None


def load(path: str = DEFAULT_MODEL_PATH):
    """Load the model and cache it. Safe to call at start-up to warm the cache.

    Reuses train.load_model, which refuses a model whose CONTRACT_VERSION or
    feature order does not match this code. Idempotent for a given path: a
    second call with the same path is a no-op, so wiring it into both start-up
    and the first predict() costs nothing.
    """
    global _pipeline, _model_path
    if _pipeline is not None and _model_path == path:
        return _pipeline
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"{path} not found. Train the model first:\n"
            f"    python src/intelligence/train.py"
        )
    payload = load_model(path)   # validates contract version and feature order
    _pipeline = payload["pipeline"]
    _model_path = path
    log.info("loaded model %s (contract %s, trained %s)",
             path, payload["contract_version"], payload.get("trained_at", "?"))
    return _pipeline


def _get_model():
    """The cached model, loading the default one only if nothing is loaded yet.

    predict() must respect a model a caller already loaded with load(path) -
    calling load() unconditionally would silently discard it and fall back to
    the default path.
    """
    if _pipeline is None:
        load()
    return _pipeline


def predict(feature_vector: list[float]) -> float:
    """Return the probability that this 24-vector is an attack, in [0.0, 1.0].

    The contract function component B imports. The vector must be the 24
    features in FEATURES_24 order - exactly what extract_features() emits.

    R3 is applied here as defence in depth: extract_features already sanitises,
    but predict() cannot assume its caller did, and a NaN reaching the model
    would poison one score silently. sanitize() is idempotent, so paying it
    twice on the live path is harmless.
    """
    if len(feature_vector) != contract.N_FEATURES:
        # A wrong length is an integration bug (the caller built the vector
        # wrong), not a malformed flow to skip. Raise so it is caught in
        # development, not swallowed in production.
        raise ValueError(
            f"predict expects {contract.N_FEATURES} features, got "
            f"{len(feature_vector)}. Build the vector with extract_features()."
        )

    # R3: non-finite -> 0.0, everything to float. The same rule the model was
    # trained under, from the same source of truth.
    vector = contract.sanitize(feature_vector)

    # A finite negative is a corrupt flow (contract: all 24 are non-negative
    # magnitudes). Offline A3 drops it; live we cannot, so we log and score
    # anyway - a tree is robust to an out-of-range value, and dropping the flow
    # would blind the IDS to it. strict=False never raises.
    problems = contract.validate(vector, strict=False)
    if problems:
        log.warning("scoring a flow that violates the contract: %s",
                    "; ".join(problems))

    model = _get_model()  # the cached model, whatever path it was loaded from

    # A one-row DataFrame with the contract column names: the Pipeline was fitted
    # on named columns, so this both silences sklearn's feature-name warning and
    # guarantees the 24 values land in the slots the model expects.
    import pandas as pd

    frame = pd.DataFrame([vector], columns=list(contract.FEATURES_24))
    probability = model.predict_proba(frame)[0][1]
    return float(probability)


def reset() -> None:
    """Drop the cached model. For tests that load a different one; not for the
    live path, where the model is loaded once and kept."""
    global _pipeline, _model_path
    _pipeline = None
    _model_path = None
