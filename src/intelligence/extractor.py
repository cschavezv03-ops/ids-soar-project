"""
The live feature extractor - component A's half of the interface with Frank.

    extract_features(flow) -> list[float]

Frank imports this and calls it once per assembled flow. It returns EXACTLY 24
floats, in the frozen order of contract.FEATURES_24, ready to hand to predict().

Parity is guaranteed by construction, not by coincidence. cicflowmeter computes
every statistic (means, stds, IAT, packet lengths) inside Flow.get_data(); this
module only SELECTS the 24 the contract needs and applies the normalisation the
CSV requires. The pcap path (offline validation) and the live path (Frank) run
the same patched Flow.get_data(), so the two cannot drift apart.

Three contract rules, and where each is handled:

    R1  time     applied HERE: cicflowmeter emits seconds, the CSV is in
                 microseconds. contract.seconds_to_contract_time() scales the
                 seven time positions by 1e6.
    R2  length   already applied in the MEASUREMENT (cicflowmeter_patches.py):
                 packet lengths are payload bytes by the time get_data() runs.
                 Nothing to do here.
    R3  values   applied HERE, last: contract.sanitize() turns NaN/inf into 0.0
                 and casts everything to float.

A malformed flow must never take the IDS down. A missing or non-numeric field
becomes NaN and is caught by sanitize(), so extract_features always returns 24
finite floats - never a KeyError, never a crash.
"""
from __future__ import annotations

from typing import Any, Mapping

from . import contract as c

# Stand-in for a field cicflowmeter did not produce for this flow. NaN (not 0.0)
# so that R3 in sanitize() is the single place that decides what "missing"
# becomes - the contract's rule, not a second copy of it here.
_MISSING = float("nan")


def features_from_dict(data: Mapping[str, Any]) -> list[float]:
    """
    Turn one cicflowmeter get_data() dict into the 24-feature contract vector.

    Kept separate from extract_features so the parity bench and the tests can
    drive it with a plain dict, without constructing Flow objects. This is the
    function that actually applies the contract; extract_features just gets the
    dict from a Flow and calls it.
    """
    # 1. Select the 24 the contract wants, in frozen order. get() (not []) so a
    #    missing key yields _MISSING instead of raising: one bad flow must not
    #    stop the pipeline.
    vector = [_to_number(data.get(name)) for name in c.FEATURES_24]

    # 2. R1 - seconds to microseconds on the seven time positions.
    vector = c.seconds_to_contract_time(vector)

    # 3. R3 - NaN/inf -> 0.0, everything cast to float. Runs last so it also
    #    cleans up anything R1 turned non-finite and any _MISSING from step 1.
    vector = c.sanitize(vector)

    return vector


def extract_features(flow: Any) -> list[float]:
    """
    Contract function imported by Frank. Receives an assembled cicflowmeter
    Flow and returns its 24-feature vector.

    Accepts either a Flow (anything exposing get_data()) or, as a convenience,
    a mapping already shaped like get_data()'s output.
    """
    if hasattr(flow, "get_data"):
        data = flow.get_data()
    elif isinstance(flow, Mapping):
        data = flow
    else:
        raise TypeError(
            "extract_features expects a cicflowmeter Flow (with .get_data()) "
            f"or a dict-like of features, got {type(flow).__name__}"
        )
    return features_from_dict(data)


def _to_number(value: Any) -> float:
    """
    Coerce one raw field to float, or to NaN if it cannot be one.

    Returning NaN (rather than raising) hands the decision to sanitize(): a
    missing field, a None, or a stray string all become 0.0 there, in one place.
    """
    if value is None:
        return _MISSING
    try:
        return float(value)
    except (TypeError, ValueError):
        return _MISSING