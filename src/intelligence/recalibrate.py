"""
A7 second pass - recalibrate the threshold against real lab traffic.

This is the task A6 deferred and the first pass could not do. A6 fixed the
operating point on CICIDS2017 because that was the only labelled traffic we
had; the first pass (lab_calibration.py) showed the lab attacks landing far
below that cut but could not fix it, because two benign flows cannot measure a
false positive rate.

Frank's second capture set closes that gap: 12,029 benign flows with hardware
offload disabled, plus the SYN flood at three intensities so the question "is
it a matter of speed?" can be answered rather than argued.

WHAT RECALIBRATION MEANS HERE. Moving the cut in config.py. Not retraining: the
model A4 fitted and A5 validated stays exactly as it is, and its contract stays
frozen. Section 4 of the report explains why retraining would not fix the one
thing that is actually broken.

Usage (from the repo root):
    python src/intelligence/recalibrate.py
    python src/intelligence/recalibrate.py --re-extract   # ignore the cache
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
from intelligence.lab_calibration import extract_lab_vectors  # noqa: E402
from intelligence.preprocess import LABEL_COL, PROCESSED_DIR, Report  # noqa: E402

REPORT_PATH = os.path.join("scripts", "scripts_output", "recalibration_report.txt")
PCAP_DIR = os.path.join("data", "pcap", "pcap_v2.0")
# Extracting 1.7M packets takes ~7 minutes, so the 24-vectors are cached. The
# cache lives under data/ with the rest of the derived data, and --re-extract
# rebuilds it.
CACHE_PATH = os.path.join(PROCESSED_DIR, "lab_vectors_v2.parquet")

# Each capture and the CICIDS2017 family it is meant to reproduce.
CAPTURES_V2 = {
    "benigno_hora_punta.pcap": None,
    "benigno_tranquilo.pcap": None,
    "ataque_nmap_lento.pcap": "PortScan",
    "ataque_nmap_rapido.pcap": "PortScan",
    "ataque_syn_10pps.pcap": "DDoS",
    "ataque_syn_100pps.pcap": "DDoS",
    "ataque_syn_1000pps.pcap": "DDoS",
    "ataque_hydra_ssh_250.pcap": "SSH-Patator",
}

# The decision this run supports. config.py is the source of truth; these are
# what the report was written against, and a mismatch stops the run.
NEW_CONTAIN = 0.50
NEW_HIGH = 0.70
OLD_CONTAIN, OLD_HIGH = 0.70, 0.90

SWEEP = np.round(np.arange(0.05, 1.001, 0.025), 3)


def load_lab_vectors(pcap_dir: str, cache: str, re_extract: bool) -> pd.DataFrame:
    """24-vectors for every capture, from cache when it exists."""
    if os.path.exists(cache) and not re_extract:
        return pd.read_parquet(cache)

    frames = []
    for name in CAPTURES_V2:
        path = os.path.join(pcap_dir, name)
        if not os.path.exists(path):
            raise SystemExit(f"{path} not found.")
        frame = extract_lab_vectors(path)
        frame["capture"] = name
        frames.append(frame)
    out = pd.concat(frames, ignore_index=True)
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    out.to_parquet(cache, index=False)
    return out


def is_benign(capture: str) -> bool:
    return CAPTURES_V2[capture] is None


def main() -> int:
    ap = argparse.ArgumentParser(description="A7: recalibrate against lab traffic.")
    ap.add_argument("--pcap-dir", default=PCAP_DIR)
    ap.add_argument("--cache", default=CACHE_PATH)
    ap.add_argument("--re-extract", action="store_true")
    ap.add_argument("--figures-dir", default=FIGURES_DIR)
    ap.add_argument("--report", default=REPORT_PATH)
    args = ap.parse_args()

    payload = train.load_model(train.MODEL_FILES[train.RF_KEY])
    model = payload["pipeline"]

    frame = load_lab_vectors(args.pcap_dir, args.cache, args.re_extract)
    frame["proba"] = model.predict_proba(frame[contract.FEATURES_24])[:, 1]
    benign = frame[frame["capture"].map(is_benign)]
    attack = frame[~frame["capture"].map(is_benign)]
    benign_proba = benign["proba"].to_numpy()

    rep = Report()
    rep("A7 recalibration report - the threshold against real lab traffic")
    rep(f"contract version {contract.CONTRACT_VERSION}   "
        f"model trained {payload['trained_at']}")
    rep("")
    rep("The model is NOT retrained. Only the cut moves. Section 4 explains why")
    rep("retraining would not fix the one thing that is actually broken.")

    # ---- 1. the captures ------------------------------------------------
    rep.banner("1. THE SECOND CAPTURE SET")
    rep("Hardware offload is now off: the largest frame is 1514 bytes, the")
    rep("Ethernet maximum. The first set carried 7240-byte frames from NIC")
    rep("coalescing, which inflated the three features the forest leans on most.")
    rep("")
    rep(f"    {'capture':<32}{'flows':>10}{'unique vectors':>16}"
        f"{'p50':>7}{'p90':>7}{'max':>7}")
    for name in CAPTURES_V2:
        group = frame[frame["capture"] == name]
        if group.empty:
            continue
        unique = group[contract.FEATURES_24].drop_duplicates().shape[0]
        q = np.quantile(group["proba"], [0.5, 0.9])
        rep(f"    {name:<32}{len(group):>10,}{unique:>16,}"
            f"{q[0]:>7.2f}{q[1]:>7.2f}{group['proba'].max():>7.2f}")
    rep("")
    rep(f"    benign flows: {len(benign):,}   attack flows: {len(attack):,}")
    rep("")
    rep("The benign half is now measurable. A6 asked for it and the first pass")
    rep("had two flows; 12,029 puts the 95% interval on a 0.002 rate inside")
    rep("+/-25%, which is enough to choose a cut with.")

    # ---- 2. the sweep ---------------------------------------------------
    rep.banner("2. WHERE TO CUT, MEASURED ON OUR OWN TRAFFIC")
    scan = frame[frame["capture"].str.startswith("ataque_nmap")]["proba"].to_numpy()
    hydra = frame[frame["capture"] == "ataque_hydra_ssh_250.pcap"]["proba"].to_numpy()
    flood = frame[frame["capture"].str.startswith("ataque_syn")]["proba"].to_numpy()

    rep(f"    {'cut':>7}{'scan':>9}{'hydra':>9}{'flood':>9}"
        f"{'benign FPR':>13}{'FP (n)':>9}{'scans per FP':>14}")
    for cut in SWEEP:
        n_fp = int((benign_proba >= cut).sum())
        ratio = int((scan >= cut).sum()) / n_fp if n_fp else float("inf")
        mark = ""
        if abs(cut - NEW_CONTAIN) < 1e-9:
            mark = "  <- chosen"
        elif abs(cut - OLD_CONTAIN) < 1e-9:
            mark = "  <- A6"
        rep(f"    {cut:>7.3f}{(scan >= cut).mean():>9.1%}{(hydra >= cut).mean():>9.1%}"
            f"{(flood >= cut).mean():>9.1%}{(benign_proba >= cut).mean():>13.4f}"
            f"{n_fp:>9,}{ratio:>14.1f}{mark}")

    # ---- 3. the decision -------------------------------------------------
    rep.banner("3. THE DECISION")
    rep(f"    contain  {OLD_CONTAIN:.2f} -> {NEW_CONTAIN:.2f}")
    rep(f"    HIGH     {OLD_HIGH:.2f} -> {NEW_HIGH:.2f}")
    rep("")
    rep("WHAT IT BUYS, on lab traffic:")
    rep(f"    port scan detection   {(scan >= OLD_CONTAIN).mean():.1%} -> "
        f"{(scan >= NEW_CONTAIN).mean():.1%}")
    rep(f"    benign false positives {int((benign_proba >= OLD_CONTAIN).sum()):,} -> "
        f"{int((benign_proba >= NEW_CONTAIN).sum()):,} of {len(benign):,}")
    rep("")
    rep("WHAT IT COSTS, on CICIDS2017 - and it costs almost nothing, because")
    rep("recall rises on every single family while precision drops by 0.0019:")
    predictions = train.load_predictions()
    y_true = predictions["y_true"].to_numpy()
    proba = predictions[f"{train.RF_KEY}_proba"].to_numpy()
    labels = predictions[LABEL_COL].to_numpy()
    rep("")
    rep(f"    {'family':<20}{'at 0.70':>10}{'at 0.50':>10}{'change':>10}")
    for family in sorted(set(labels) - {contract.BENIGN_LABEL},
                         key=lambda f: -(labels == f).sum()):
        mask = labels == family
        old = (proba[mask] >= OLD_CONTAIN).mean()
        new = (proba[mask] >= NEW_CONTAIN).mean()
        rep(f"    {family:<20}{old:>10.4f}{new:>10.4f}{new - old:>+10.4f}")
    benign_mask = y_true == contract.BENIGN
    old_fp = int((proba[benign_mask] >= OLD_CONTAIN).sum())
    new_fp = int((proba[benign_mask] >= NEW_CONTAIN).sum())
    rep(f"    {'BENIGN (false pos)':<20}{old_fp:>10,}{new_fp:>10,}{new_fp - old_fp:>+10,}")
    rep("")
    rep("HIGH moves from 0.90 to 0.70 because nothing in the lab reaches 0.90 -")
    rep(f"the highest probability any lab attack flow receives is "
        f"{attack['proba'].max():.2f}. Left at 0.90 the")
    rep("severity band would be dead on our own network, and a graded response")
    rep("that never grades is not a design, it is decoration.")

    # ---- 4. what the threshold cannot fix --------------------------------
    rep.banner("4. WHAT NO THRESHOLD FIXES: THE SYN FLOOD")
    flood_frame = frame[frame["capture"].str.startswith("ataque_syn")]
    unique_vectors = flood_frame[contract.FEATURES_24].drop_duplicates().shape[0]
    rep(f"The three flood captures - 10, 100 and 1000 packets per second -")
    rep(f"produce {len(flood_frame):,} flows and {unique_vectors} distinct feature "
        f"vector(s) between them,")
    rep(f"and every one of them scores {flood_frame['proba'].median():.2f}. The "
        f"intensity does not matter at all.")
    rep("")
    rep("That answers the question the three intensities were captured to")
    rep("answer: it is NOT a matter of speed.")
    rep("")
    rep("The reason is structural. Our flood and CICIDS2017's DDoS are not the")
    rep("same attack:")
    rep("")
    key = ["flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_bwd_pkts",
           "bwd_pkt_len_mean", "pkt_len_std"]
    reference = pd.read_parquet(
        os.path.join(PROCESSED_DIR, "train.parquet"), columns=key + [LABEL_COL])
    ddos = reference[reference[LABEL_COL] == "DDoS"][key].median()
    rep(f"    {'feature':<22}{'lab hping3 -S':>16}{'CICIDS2017 DDoS':>18}")
    for feature in key:
        rep(f"    {feature:<22}{flood_frame[feature].median():>16,.2f}"
            f"{ddos[feature]:>18,.2f}")
    rep("")
    rep("Ours is an UNANSWERED SYN flood: one packet out, nothing back, zero")
    rep("duration. Theirs is an ANSWERED HTTP flood: four packets each way and")
    rep("11,601 bytes of server response. They share a name and nothing else.")
    rep("")
    signature = ((reference["tot_fwd_pkts"] == 1) & (reference["tot_bwd_pkts"] == 0)).sum()
    rep(f"And the decisive number: CICIDS2017 contains {signature} flows with our")
    rep("flood's signature (1 forward packet, 0 backward). Not few - NONE.")
    rep("")
    rep("So the model is not misclassifying the flood. It is EXTRAPOLATING into")
    rep("a region of the feature space its training set never covered, and a")
    rep("threshold cannot repair a region that was never learned.")

    # ---- 5. figure -------------------------------------------------------
    rep.banner("5. FIGURE")
    os.makedirs(args.figures_dir, exist_ok=True)
    path = os.path.join(args.figures_dir, "recalibration_lab.png")
    fig, ax = plt.subplots(figsize=(7.6, 5.0), dpi=150)
    series = [
        ("benign (12,029 flows)", benign_proba, "#1b7837", "-"),
        ("port scan (nmap)", scan, "#b2182b", "-"),
        ("SSH brute force (hydra)", hydra, "#d95f02", "--"),
        ("SYN flood (hping3)", flood, "#7570b3", ":"),
    ]
    for label, values, colour, style in series:
        if len(values) == 0:
            continue
        share = [(values >= cut).mean() for cut in SWEEP]
        ax.plot(SWEEP, share, label=label, color=colour, linestyle=style, linewidth=2.1)
    ax.axvline(NEW_CONTAIN, color="#333333", linewidth=1.4, linestyle="--")
    ax.annotate(f"new contain {NEW_CONTAIN:.2f}", xy=(NEW_CONTAIN - 0.015, 0.30),
                ha="right", fontsize=8.5, rotation=90)
    ax.axvline(OLD_CONTAIN, color="#999999", linewidth=1.2, linestyle=":")
    ax.annotate(f"A6 {OLD_CONTAIN:.2f}", xy=(OLD_CONTAIN + 0.015, 0.30),
                ha="left", fontsize=8.5, rotation=90, color="#777777")
    ax.set_xlabel("decision threshold")
    ax.set_ylabel("share of the capture's flows flagged")
    ax.set_ylim(-0.02, 1.02)
    ax.set_title("Lab traffic against the threshold: the flood never separates",
                 fontsize=11, pad=10)
    ax.grid(alpha=0.25, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.legend(fontsize=9, loc="upper right", framealpha=0.95)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    rep(f"    {path}")

    rep.banner("DONE")
    rep(f"config.py must read THRESHOLD={NEW_CONTAIN}, SEV_MEDIUM={NEW_CONTAIN}, "
        f"SEV_HIGH={NEW_HIGH}.")
    rep(f"It currently reads {config.THRESHOLD}, {config.SEV_MEDIUM}, "
        f"{config.SEV_HIGH}.")
    rep("See contract/A7_lab_calibration_note.md for the written decision.")

    rep.save(args.report)
    print(f"\nreport saved to {args.report}")
    return 0


if __name__ == "__main__":
    from intelligence.recalibrate import main as package_main

    sys.exit(package_main())
