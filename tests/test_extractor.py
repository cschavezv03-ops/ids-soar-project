"""
Tests for extract_features - component A's half of the interface with Frank.

Each test corresponds to a concrete way the extractor could return a vector
that looks fine and is wrong, or could take the IDS down on traffic it should
have survived: a feature pulled from the wrong position, R1 applied to the
wrong columns or not at all, a malformed flow raising instead of degrading, a
non-finite value reaching the model.

Run:  pytest -v tests/test_extractor.py
"""
import math
from pathlib import Path

import pytest

from intelligence import contract as c
from intelligence.extractor import (
    extract_features,
    features_from_dict,
    _to_number,
)

PCAP = Path("data/pcap/synthetic_smoke.pcap")


def _clean_flow(value: float = 1.0) -> dict:
    """A get_data()-shaped dict with every contract feature set to `value`."""
    return {name: value for name in c.FEATURES_24}


# --- shape -----------------------------------------------------------------

def test_returns_exactly_24_floats():
    """If the length ever drifts from 24, predict() receives the wrong shape
    and either crashes or, worse, silently misaligns every feature."""
    vector = features_from_dict(_clean_flow())
    assert len(vector) == c.N_FEATURES
    assert all(isinstance(x, float) for x in vector)


def test_all_features_selected_in_contract_order():
    """A feature read from the wrong key would put, say, a byte count where the
    model expects a duration. Give each feature a distinct value and check every
    position carries its own."""
    data = {name: float(i) for i, name in enumerate(c.FEATURES_24)}
    vector = features_from_dict(data)
    # Non-time positions pass through untouched; time positions are scaled by R1.
    for i in range(c.N_FEATURES):
        expected = float(i) * (c.SECONDS_TO_MICROSECONDS if i in c.TIME_IDX else 1)
        assert vector[i] == expected, f"position {i} ({c.FEATURES_24[i]})"


# --- R1: time --------------------------------------------------------------

def test_r1_scales_only_time_positions():
    """R1 turns seconds into microseconds. Applied to a non-time feature it
    would inflate a packet count by a million; not applied to a time feature it
    would leave the live vector 1e6 times smaller than the CSV."""
    vector = features_from_dict(_clean_flow(1.0))
    for i in range(c.N_FEATURES):
        if i in c.TIME_IDX:
            assert vector[i] == float(c.SECONDS_TO_MICROSECONDS), c.FEATURES_24[i]
        else:
            assert vector[i] == 1.0, c.FEATURES_24[i]


def test_r1_duration_matches_expected_microseconds():
    """A concrete anchor: 0.06 s of flow must reach the model as 60000 us, the
    unit the CSV trained on."""
    data = _clean_flow(0.0)
    data["flow_duration"] = 0.06
    vector = features_from_dict(data)
    assert vector[0] == pytest.approx(60000.0)


# --- R3: value handling ----------------------------------------------------

def test_non_finite_values_become_zero():
    """inf and NaN come from dividing by a zero-duration flow - exactly what a
    single-packet scan probe produces. If they reach the model as inf/NaN the
    tree comparisons misbehave; R3 must have turned them into 0.0."""
    data = _clean_flow(1.0)
    data["flow_byts_s"] = math.inf
    data["flow_pkts_s"] = math.nan
    vector = features_from_dict(data)
    assert all(math.isfinite(x) for x in vector)
    assert vector[c.FEATURES_24.index("flow_byts_s")] == 0.0
    assert vector[c.FEATURES_24.index("flow_pkts_s")] == 0.0


def test_output_always_passes_contract_validation():
    """Whatever comes in, the vector handed to Frank must satisfy the contract:
    24 finite, non-negative floats."""
    data = _clean_flow(2.0)
    data["flow_byts_s"] = math.inf
    assert c.validate(features_from_dict(data), strict=False) == []


# --- robustness: a bad flow must not crash the IDS -------------------------

def test_missing_keys_do_not_raise():
    """cicflowmeter can emit a flow without every field. get()-with-sentinel
    means a missing key becomes 0.0, never a KeyError that stops the pipeline."""
    vector = features_from_dict({"flow_duration": 0.01})  # 23 keys absent
    assert len(vector) == c.N_FEATURES
    assert c.validate(vector, strict=False) == []


def test_none_and_junk_values_become_zero():
    """A None or a stray string in one field must degrade to 0.0, not blow up
    the whole flow."""
    data = _clean_flow(1.0)
    data["tot_fwd_pkts"] = None
    data["totlen_fwd_pkts"] = "not a number"
    vector = features_from_dict(data)
    assert vector[c.FEATURES_24.index("tot_fwd_pkts")] == 0.0
    assert vector[c.FEATURES_24.index("totlen_fwd_pkts")] == 0.0


def test_to_number_coerces_and_degrades():
    """The coercion helper in isolation: real numbers pass through, the rest
    becomes NaN for sanitize() to zero out later."""
    assert _to_number(3) == 3.0
    assert _to_number("2.5") == 2.5
    assert math.isnan(_to_number(None))
    assert math.isnan(_to_number("oops"))
    assert math.isnan(_to_number([1, 2]))


# --- interface: what Frank actually calls ----------------------------------

def test_extract_features_accepts_a_mapping():
    """The convenience path: a dict shaped like get_data() output works without
    constructing a Flow. This is what the parity bench and tests lean on."""
    assert len(extract_features(_clean_flow())) == c.N_FEATURES


def test_extract_features_accepts_a_flow_like_object():
    """The real path: anything exposing get_data() is treated as a Flow."""
    class FakeFlow:
        def get_data(self):
            return _clean_flow(5.0)
    vector = extract_features(FakeFlow())
    assert len(vector) == c.N_FEATURES
    assert vector[1] == 5.0  # tot_fwd_pkts, a non-time position


def test_extract_features_rejects_wrong_type():
    """Passing something that is neither a Flow nor a mapping is a programming
    error, not a bad flow - it must fail loudly, unlike a corrupt field."""
    with pytest.raises(TypeError):
        extract_features(42)


# --- end to end: real Flow objects from the synthetic pcap -----------------

@pytest.mark.skipif(not PCAP.exists(), reason="synthetic pcap not generated")
def test_end_to_end_on_synthetic_capture():
    """The whole path on real Flow objects: patched cicflowmeter builds flows
    from the pcap, extract_features turns each into a valid 24-vector, and the
    two-packet scan probes (single interval) survive without crashing."""
    from intelligence.cicflowmeter_patches import apply_patches
    apply_patches()

    import cicflowmeter.flow as flow_module
    from cicflowmeter.sniffer import create_sniffer

    captured = []
    original = flow_module.Flow.get_data

    def spy(self, *args, **kwargs):
        data = original(self, *args, **kwargs)
        captured.append(dict(data))
        return data

    flow_module.Flow.get_data = spy
    try:
        sniffer, session = create_sniffer(
            input_file=str(PCAP), input_interface=None, output_mode="csv",
            output="/tmp/extractor_e2e.csv", input_directory=None,
            fields=None, verbose=False,
        )
        sniffer.start()
        sniffer.join()
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        session.flush_flows()
    finally:
        flow_module.Flow.get_data = original

    assert captured, "no flows captured from the pcap"
    for data in captured:
        vector = extract_features(data)
        assert c.validate(vector, strict=False) == []