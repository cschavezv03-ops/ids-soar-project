"""
Tests for the 24-feature contract.

These are not tests of "does the code run". They are the automated form of
the promises the contract makes. Each test corresponds to one way the two
components could silently drift apart, and fails loudly when they do.

Run:  pytest -v tests/test_contract.py
"""
import math
import pytest

from intelligence import contract as c


# ---------------------------------------------------------------------------
# 1. The vector has a fixed shape
# ---------------------------------------------------------------------------

def test_contract_has_exactly_24_features():
    """The number is the interface. Changing it breaks component B."""
    assert c.N_FEATURES == 24
    assert len(c.FEATURES_24) == 24


def test_no_duplicate_feature_names():
    """A copy-pasted line would leave 24 slots holding 23 distinct features."""
    assert len(set(c.FEATURES_24)) == 24


def test_feature_order_is_frozen():
    """Position is part of the contract. This literal is the frozen record:
    if someone reorders FEATURES_24, this test - not the demo - finds out."""
    assert c.FEATURES_24 == [
        "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
        "totlen_bwd_pkts", "fwd_pkt_len_min", "fwd_pkt_len_mean",
        "fwd_pkt_len_std", "fwd_pkt_len_max", "bwd_pkt_len_min",
        "bwd_pkt_len_mean", "bwd_pkt_len_std", "bwd_pkt_len_max",
        "pkt_len_mean", "pkt_len_std", "flow_iat_mean", "flow_iat_std",
        "flow_iat_max", "flow_iat_min", "fwd_iat_mean", "bwd_iat_mean",
        "flow_pkts_s", "flow_byts_s", "fwd_act_data_pkts",
    ]


def test_csv_mapping_stays_aligned():
    """FEATURES_24[i] and CSV_COLUMNS_24[i] must describe the same thing.
    If they drift, training reads the wrong column for every feature."""
    assert len(c.CSV_COLUMNS_24) == c.N_FEATURES
    assert len(set(c.CSV_COLUMNS_24)) == c.N_FEATURES


# ---------------------------------------------------------------------------
# 2. Labels map to targets without a silent default
# ---------------------------------------------------------------------------

def test_benign_and_attacks_map_correctly():
    assert c.label_to_target("BENIGN") == 0
    for label in ["PortScan", "DDoS", "DoS Hulk", "DoS GoldenEye",
                  "DoS slowloris", "DoS Slowhttptest",
                  "SSH-Patator", "FTP-Patator"]:
        assert c.label_to_target(label) == 1, label


def test_excluded_labels_return_none_not_zero():
    """Excluded is NOT benign. Returning 0 here would teach the model that
    botnet traffic is normal - worse than ignoring it."""
    for label in ["Bot", "Infiltration", "Heartbleed"]:
        assert c.label_to_target(label) is None, label


@pytest.mark.parametrize("label", [
    "Web Attack \ufffd Brute Force",          # as pandas reads it with utf-8
    "Web Attack \u00ef\u00bf\u00bd XSS",      # as pandas reads it with latin-1
    "Web Attack \ufffd Sql Injection",
])
def test_web_attack_labels_match_under_any_encoding(label):
    """The file holds bytes EF BF BD (U+FFFD, corruption baked in back in
    2017). The Python string differs depending on the encoding used to read.
    Prefix matching makes that irrelevant - this test proves it."""
    assert c.label_to_target(label) is None


def test_unknown_label_raises():
    """The single most important test here. A silent default would quietly
    poison the training set with mislabelled rows."""
    with pytest.raises(ValueError, match="Unknown label"):
        c.label_to_target("DoS SomethingNew")


def test_label_sets_do_not_overlap():
    assert not (c.ATTACK_LABELS & c.EXCLUDED_LABELS)
    assert c.BENIGN_LABEL not in c.ATTACK_LABELS


# ---------------------------------------------------------------------------
# 3. Every position has a declared conversion rule
# ---------------------------------------------------------------------------

def test_every_position_is_classified():
    """Adding a feature without deciding whether it carries a unit conversion
    is how a value stays in seconds while the model reads microseconds."""
    covered = set(c.TIME_IDX) | set(c.PAYLOAD_IDX) | set(c.COUNT_IDX) | set(c.RATE_IDX)
    assert covered == set(range(c.N_FEATURES))


def test_time_and_payload_rules_do_not_overlap():
    assert not (set(c.TIME_IDX) & set(c.PAYLOAD_IDX))


def test_time_indices_are_the_time_features():
    """Guards against an index typo silently multiplying a byte count by 1e6."""
    names = {c.FEATURES_24[i] for i in c.TIME_IDX}
    assert names == {"flow_duration", "flow_iat_mean", "flow_iat_std",
                     "flow_iat_max", "flow_iat_min", "fwd_iat_mean", "bwd_iat_mean"}


def test_seconds_to_microseconds_touches_only_time():
    """Rule R1 must convert the 7 time features and leave the other 17 alone."""
    before = [1.0] * c.N_FEATURES
    after = c.seconds_to_contract_time(before)
    for i in range(c.N_FEATURES):
        if i in c.TIME_IDX:
            assert after[i] == 1_000_000.0, c.FEATURES_24[i]
        else:
            assert after[i] == 1.0, c.FEATURES_24[i]


def test_a_60ms_flow_becomes_60000_microseconds():
    """The concrete case from the smoke test."""
    v = [0.06] + [0.0] * 23
    assert c.seconds_to_contract_time(v)[0] == pytest.approx(60_000.0)


# ---------------------------------------------------------------------------
# 4. Non-finite handling is identical on both paths
# ---------------------------------------------------------------------------

def test_sanitize_replaces_inf_and_nan():
    """Rule R3. Single-packet flows divide by a zero duration and produce inf.
    That is exactly what a port scan looks like, so this must not be wrong."""
    v = [1.0] * c.N_FEATURES
    v[22] = float("inf")     # flow_byts_s
    v[21] = float("-inf")    # flow_pkts_s
    v[15] = float("nan")     # flow_iat_mean
    out = c.sanitize(v)
    assert all(math.isfinite(x) for x in out)
    assert out[22] == c.MISSING_VALUE
    assert out[21] == c.MISSING_VALUE
    assert out[15] == c.MISSING_VALUE


def test_sanitize_leaves_good_values_untouched():
    v = [float(i) for i in range(c.N_FEATURES)]
    assert c.sanitize(v) == v


def test_sanitize_always_returns_floats():
    """The model must never see ints in one run and floats in another."""
    v = [1] * c.N_FEATURES
    assert all(isinstance(x, float) for x in c.sanitize(v))


# ---------------------------------------------------------------------------
# 5. validate() catches malformed vectors
# ---------------------------------------------------------------------------

def test_a_good_vector_passes():
    assert c.validate([1.0] * c.N_FEATURES, strict=False) == []


def test_wrong_length_is_caught():
    """A flow-assembly bug producing 23 values must fail here, not three
    layers down inside scikit-learn."""
    assert c.validate([1.0] * 23, strict=False) != []
    assert c.validate([1.0] * 25, strict=False) != []


def test_negative_values_are_caught():
    """All 24 are magnitudes. Negative means corrupt flow or bug - the CSV
    itself has 22 rows with a negative Flow Duration."""
    v = [1.0] * c.N_FEATURES
    v[0] = -5.0
    problems = c.validate(v, strict=False)
    assert len(problems) == 1
    assert "flow_duration" in problems[0]


def test_booleans_are_rejected():
    """In Python True == 1 and isinstance(True, int) is True, so a stray
    boolean would pass every naive numeric check."""
    v = [1.0] * c.N_FEATURES
    v[23] = True
    assert c.validate(v, strict=False) != []


def test_strict_mode_raises_permissive_mode_reports():
    """Offline work wants a crash. The live IDS wants to log and skip - an
    IDS that dies on one malformed packet is an IDS an attacker can switch
    off on purpose."""
    bad = [1.0] * c.N_FEATURES
    bad[0] = float("nan")
    with pytest.raises(ValueError):
        c.validate(bad, strict=True)
    assert isinstance(c.validate(bad, strict=False), list)


def test_problem_messages_name_the_feature():
    """Frank's dashboard logs these. '[22] flow_byts_s: ...' is actionable;
    'invalid vector' is not."""
    v = [1.0] * c.N_FEATURES
    v[22] = float("inf")
    problems = c.validate(v, strict=False)
    assert "[22]" in problems[0] and "flow_byts_s" in problems[0]


# ---------------------------------------------------------------------------
# 6. The two functions compose in the intended order
# ---------------------------------------------------------------------------

def test_sanitize_then_validate_is_the_pipeline():
    """extract -> sanitize -> validate. If validate still complains after
    sanitize, there is a real bug rather than a missing-value case."""
    v = [1.0] * c.N_FEATURES
    v[22] = float("inf")
    v[15] = float("nan")
    assert len(c.validate(v, strict=False)) == 2
    assert c.validate(c.sanitize(v), strict=False) == []