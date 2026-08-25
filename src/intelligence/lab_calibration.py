"""
A7, first pass - run the lab captures through the real model.

WHAT THIS IS. The attack half of A7, which needs nothing from anyone: the lab
pcaps already exist, A2 validated the extractor on them, and A4 fitted the
model. So we can already answer the question A5 and A6 left open - does traffic
from OUR network land where the model expects it to?

WHAT THIS IS NOT. It is not the whole of A7, and it does not recalibrate
anything. The other half - the false positive rate on the lab's own benign
traffic - CANNOT be measured with what exists today: the two benign captures
yield two flows between them. Section 5 of the report quantifies exactly how
short that falls and what to request instead. Measuring an attack that we
staged ourselves is the easy half; a detector is judged by what it does to the
other 99% of the traffic.

RECALIBRATE MEANS MOVE THE THRESHOLD, NOT RETRAIN. A1 section 9 worded A7 as
"the model learns our lab's real pattern", which reads as retraining. With a few
thousand lab flows against 1.6M from CICIDS2017 that would discard the model A4
and A5 validated, and would need the contract frozen all over again. This module
therefore measures; if the numbers disagree with A6, what moves is the cut in
config.py.

Usage (from the repo root):
    python src/intelligence/lab_calibration.py
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Reuse the extraction the profiler already uses. It monkeypatches cicflowmeter
# to spy on get_data(), which is fiddly enough that a second copy of it would
# eventually drift from the one A2 validated.
sys.path.insert(0, "scripts")

from common import config  # noqa: E402
from intelligence import contract  # noqa: E402
from intelligence import train  # noqa: E402
from intelligence.preprocess import LABEL_COL, PROCESSED_DIR, Report  # noqa: E402

REPORT_PATH = os.path.join("scripts", "scripts_output", "lab_calibration_report.txt")
PCAP_DIR = os.path.join("data", "pcap")
TRAIN_PARQUET = os.path.join(PROCESSED_DIR, "train.parquet")

# Each lab capture and the CICIDS2017 family it is meant to reproduce.
# `None` means benign; the synthetic smoke pcap is excluded because it is a
# hand-built parity fixture, not traffic.
CAPTURES = [
    ("benigno_ssh.pcap", None),
    ("benigno_web.pcap", None),
    ("portscan_lento_corrected.pcap", "PortScan"),
    ("portscan_rapido_corrected.pcap", "PortScan"),
    ("syn_flood_corrected.pcap", "DDoS"),
    ("ssh_bruteforce.pcap", "SSH-Patator"),
]

# The features the forest actually leans on (top of feature_importances_),
# plus the two that carry the "fast or slow" argument.
COMPARE_FEATURES = [
    "bwd_pkt_len_mean", "bwd_pkt_len_std", "bwd_pkt_len_max",
    "pkt_len_mean", "pkt_len_std", "flow_duration", "flow_pkts_s",
]

# How many benign flows a credible false-positive measurement needs. See the
# report: with the FPR A6 measured, fewer than a few thousand cannot tell
# "fine" apart from "ten times worse".
BENIGN_FLOWS_NEEDED = 10_000


def extract_lab_vectors(pcap_path: str) -> pd.DataFrame:
    """One row per flow, 24 columns, in contract order."""
    from pathlib import Path

    from profile_pcap import extract_all

    vectors = extract_all(Path(pcap_path))
    return pd.DataFrame(vectors, columns=contract.FEATURES_24)


def score(model, frame: pd.DataFrame) -> np.ndarray:
    """Attack probability for each flow. Same Pipeline the system will load."""
    return model.predict_proba(frame)[:, 1]


def band_of(proba: float) -> str:
    if proba >= config.SEV_HIGH:
        return "HIGH"
    if proba >= config.THRESHOLD:
        return "MEDIUM"
    return "ignored"


def reference_medians(families) -> pd.DataFrame:
    """Median of the comparison features per CICIDS2017 family, from TRAIN.

    Training rather than test: this is the distribution the model actually
    learned from, which is what a lab capture has to resemble.
    """
    frame = pd.read_parquet(TRAIN_PARQUET, columns=COMPARE_FEATURES + [LABEL_COL])
    wanted = [f for f in families if f] + [contract.BENIGN_LABEL]
    return frame[frame[LABEL_COL].isin(wanted)].groupby(LABEL_COL)[
        COMPARE_FEATURES].median()


def main() -> int:
    ap = argparse.ArgumentParser(description="A7 first pass: lab captures vs the model.")
    ap.add_argument("--pcap-dir", default=PCAP_DIR)
    ap.add_argument("--report", default=REPORT_PATH)
    args = ap.parse_args()

    model_path = train.MODEL_FILES[train.RF_KEY]
    if not os.path.exists(model_path):
        raise SystemExit(f"{model_path} not found. Run A4 first.")

    payload = train.load_model(model_path)   # refuses a contract mismatch
    model = payload["pipeline"]

    rep = Report()
    rep("A7 first pass - the lab captures through the Random Forest")
    rep(f"contract version {contract.CONTRACT_VERSION}   "
        f"model trained {payload['trained_at']}")
    rep(f"operating point from config.py: contain >= {config.THRESHOLD}, "
        f"HIGH >= {config.SEV_HIGH}")
    rep("")
    rep("Nothing was retrained and no threshold was moved. This measures where")
    rep("our own traffic lands. It is the ATTACK half of A7; the benign half")
    rep("cannot be measured with what exists today - see section 7.")

    # ---- 1. extraction -------------------------------------------------
    rep.banner("1. CAPTURES")
    results = {}
    for name, family in CAPTURES:
        path = os.path.join(args.pcap_dir, name)
        if not os.path.exists(path):
            rep(f"    {name:<34} NOT FOUND - skipped")
            continue
        frame = extract_lab_vectors(path)
        proba = score(model, frame) if len(frame) else np.array([])
        results[name] = {"family": family, "frame": frame, "proba": proba}
        rep(f"    {name:<34}{len(frame):>7,} flows   "
            f"expected: {family or 'BENIGN'}")

    if not results:
        raise SystemExit(f"No captures found in {args.pcap_dir}.")

    # ---- 2. where each capture lands ------------------------------------
    rep.banner("2. WHERE EACH CAPTURE LANDS")
    rep("Share of each capture's flows falling in each severity band, and the")
    rep("median probability the model assigns.")
    rep("")
    rep(f"    {'capture':<34}{'n':>7}{'median p':>11}"
        f"{'ignored':>10}{'MEDIUM':>9}{'HIGH':>8}{'>=0.70':>9}")
    for name, r in results.items():
        proba, n = r["proba"], len(r["frame"])
        if n == 0:
            rep(f"    {name:<34}{0:>7}   (no flows extracted)")
            continue
        bands = pd.Series([band_of(p) for p in proba]).value_counts()
        rep(f"    {name:<34}{n:>7,}{np.median(proba):>11.4f}"
            f"{bands.get('ignored', 0) / n:>10.1%}{bands.get('MEDIUM', 0) / n:>9.1%}"
            f"{bands.get('HIGH', 0) / n:>8.1%}"
            f"{(proba >= config.THRESHOLD).mean():>9.1%}")

    rep("")
    rep("For the ATTACK captures the last column is detection rate per flow.")
    rep("For the BENIGN captures it is the false positive rate - on a sample far")
    rep("too small to mean anything, which is precisely the finding in section 7.")

    # ---- 3. feature-space comparison ------------------------------------
    rep.banner("3. DOES OUR TRAFFIC LOOK LIKE WHAT THE MODEL LEARNED?")
    rep("Medians of the features the forest leans on most, lab capture against")
    rep("the CICIDS2017 family it is meant to reproduce. A large gap here is the")
    rep("domain shift A5 section 6.3 predicted, made concrete.")
    reference = reference_medians([f for _, f in CAPTURES])

    for name, r in results.items():
        if len(r["frame"]) == 0:
            continue
        family = r["family"] or contract.BENIGN_LABEL
        if family not in reference.index:
            continue
        rep("")
        rep(f"  {name}   vs   CICIDS2017 '{family}'")
        rep(f"      {'feature':<22}{'lab':>16}{'CICIDS2017':>16}{'ratio':>12}")
        lab_med = r["frame"][COMPARE_FEATURES].median()
        for feature in COMPARE_FEATURES:
            lab, ref = float(lab_med[feature]), float(reference.loc[family, feature])
            ratio = (lab / ref) if ref else float("inf") if lab else 1.0
            shown = "     n/a" if ref == 0 and lab == 0 else f"{ratio:>12,.2f}"
            rep(f"      {feature:<22}{lab:>16,.2f}{ref:>16,.2f}{shown}")

    # ---- 4. verdict per capture -----------------------------------------
    rep.banner("4. VERDICT PER ATTACK CAPTURE")
    for name, r in results.items():
        if r["family"] is None or len(r["frame"]) == 0:
            continue
        n = len(r["frame"])
        detected = float((r["proba"] >= config.THRESHOLD).mean())
        # The SOAR groups flows per source IP into one case, so what matters
        # operationally is whether ANY flow of the attack is caught.
        missed_all = (1 - detected) ** n
        rep(f"    {name}")
        rep(f"        per-flow detection      {detected:.4f}  ({int(detected * n):,} of {n:,})")
        rep(f"        P(SOAR misses it all)   {missed_all:.3e}   over {n:,} flows")

    # ---- 4b. is it the threshold, or does the model not transfer? -------
    rep.banner("5. THRESHOLD OR TRANSFER? THE DIAGNOSTIC THAT SEPARATES THEM")
    rep("If a capture's probabilities sit just under the cut, the fix is the")
    rep("cut. If they sit down among the benign traffic, no cut helps and the")
    rep("model does not transfer. These are different problems with different")
    rep("owners, so the report must not collapse them into 'detection is low'.")
    rep("")
    sweep_cuts = (0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70)
    rep(f"    {'capture':<34}{'n':>7}" + "".join(f"{c_:>8.2f}" for c_ in sweep_cuts))
    for name, r in results.items():
        if len(r["frame"]) == 0:
            continue
        rep(f"    {name:<34}{len(r['frame']):>7,}"
            + "".join(f"{(r['proba'] >= c_).mean():>8.1%}" for c_ in sweep_cuts))
    rep("")
    rep(f"    {'capture':<34}{'p10':>8}{'median':>9}{'p90':>8}{'max':>8}")
    for name, r in results.items():
        if len(r["frame"]) == 0:
            continue
        q = np.quantile(r["proba"], [0.1, 0.5, 0.9])
        rep(f"    {name:<34}{q[0]:>8.2f}{q[1]:>9.2f}{q[2]:>8.2f}"
            f"{r['proba'].max():>8.2f}")

    # ---- 4c. capture quality --------------------------------------------
    rep.banner("6. CAPTURE QUALITY: PACKETS LARGER THAN THE MTU")
    rep("A packet longer than 1500 bytes did not travel that way. It is the")
    rep("NIC coalescing several segments before the capture sees them (GRO/LRO/")
    rep("TSO). It matters here more than usual: the three features the forest")
    rep("leans on hardest are bwd_pkt_len_mean, _std and _max, and coalescing")
    rep("inflates all three. CICIDS2017 carries no such artefact, so this alone")
    rep("moves our traffic away from what the model learned.")
    rep("")
    rep(f"    {'capture':<34}{'fwd max':>10}{'bwd max':>10}{'flows > 1500 B':>17}")
    for name, r in results.items():
        frame = r["frame"]
        if len(frame) == 0:
            continue
        oversized = int(((frame["bwd_pkt_len_max"] > 1500)
                         | (frame["fwd_pkt_len_max"] > 1500)).sum())
        rep(f"    {name:<34}{frame['fwd_pkt_len_max'].max():>10,.0f}"
            f"{frame['bwd_pkt_len_max'].max():>10,.0f}"
            f"{f'{oversized}/{len(frame)}':>17}")
    rep("")
    rep("Fix at capture time, not in the extractor - the extractor must keep")
    rep("measuring what is on the wire:")
    rep("    sudo ethtool -K <iface> gro off lro off tso off gso off")

    # ---- 5. the benign gap ----------------------------------------------
    rep.banner("7. THE HALF THAT CANNOT BE MEASURED YET")
    benign_flows = sum(len(r["frame"]) for r in results.values() if r["family"] is None)
    rep(f"Benign flows available in the lab captures: {benign_flows}")
    rep("")
    rep("A6 measured a false positive rate of 0.00189 on CICIDS2017 benign")
    rep("traffic. To confirm or refute that number on OUR network we need enough")
    rep("benign flows for the estimate to have a usable interval:")
    rep("")
    rep(f"    {'benign flows':>14}{'expected FP':>14}{'95% interval on the rate':>32}")
    from scipy import stats
    for n in (benign_flows, 1_000, 5_000, BENIGN_FLOWS_NEEDED, 50_000):
        if n <= 0:
            continue
        k = 0.00189 * n
        lo, hi = stats.beta.ppf([0.025, 0.975], max(k, 0.5), n - k + 0.5)
        mark = "  <- what we have" if n == benign_flows else ""
        rep(f"    {n:>14,}{k:>14.1f}      [{lo:.5f} , {hi:.5f}]{mark}")
    rep("")
    rep("With what we have the interval spans from a fraction of a percent to")
    rep("most of the traffic: it cannot tell a working detector apart from one")
    rep("that blocks two users in three. This is not a detail to note in passing")
    rep("- it is the number the whole containment decision rests on.")
    rep("")
    rep("WHY MORE SSH SESSIONS WILL NOT FIX IT. A2 section 5 already flagged it:")
    rep("the benign captures are single long sessions, so one SSH login is ONE")
    rep("flow, not hundreds. Reaching thousands of benign flows needs sustained,")
    rep("varied traffic from several hosts - browsing, downloads, DNS - which is")
    rep("also the FAST benign profile that A5 section 6.3 identified as the")
    rep("riskiest, because CICIDS2017 associates speed with normal traffic.")

    rep.banner("DONE")
    rep("Attack half measured. Benign half blocked on captures that do not")
    rep("exist yet. No threshold was moved; config.py is untouched.")

    rep.save(args.report)
    print(f"\nreport saved to {args.report}")
    return 0


if __name__ == "__main__":
    from intelligence.lab_calibration import main as package_main

    sys.exit(package_main())
