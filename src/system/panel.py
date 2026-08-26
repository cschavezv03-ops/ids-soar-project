
import os
import sqlite3
import time

import pandas as pd
import streamlit as st

from src.common import config
from src.system import containment

REFRESH_SECONDS = 5

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def read_cases():
    """Every case, newest activity first. Empty frame if the DB is not there."""
    if not os.path.exists(config.CASES_DB):
        return pd.DataFrame()

    connection = sqlite3.connect(config.CASES_DB)
    try:
        return pd.read_sql_query(
            "SELECT case_id, src_ip, severity, action, probability,"
            " created_at, updated_at, alert_count"
            " FROM cases ORDER BY updated_at DESC",
            connection,
        )
    finally:
        connection.close()


def read_alerts(limit=50):
    if not os.path.exists(config.CASES_DB):
        return pd.DataFrame()

    connection = sqlite3.connect(config.CASES_DB)
    try:
        return pd.read_sql_query(
            "SELECT case_id, src_ip, probability, timestamp"
            " FROM alerts ORDER BY id DESC LIMIT ?",
            connection,
            params=(limit,),
        )
    finally:
        connection.close()


def close_case(case_id):
    """
    Mark a case resolved. The row stays in SQLite as evidence; the running
    SOAR engine picks the change up on its next correlated alert.
    """
    connection = sqlite3.connect(config.CASES_DB)
    connection.execute(
        "UPDATE cases SET action = 'CLOSED' WHERE case_id = ?", (case_id,)
    )
    connection.commit()
    connection.close()


def read_latency():
    if not os.path.exists(config.LATENCY_LOG):
        return None

    values = []
    with open(config.LATENCY_LOG) as handle:
        for line in handle:
            parts = line.strip().split(",")
            if len(parts) == 5:
                try:
                    values.append(float(parts[4]))
                except ValueError:
                    continue

    if not values:
        return None

    values.sort()
    return {
        "n": len(values),
        "p50": values[min(int(len(values) * 0.50), len(values) - 1)],
        "p95": values[min(int(len(values) * 0.95), len(values) - 1)],
    }


def main():
    st.set_page_config(page_title="IDS + SOAR", layout="wide")

    st.title("IDS + SOAR")
    st.caption(
        "Network flows scored by a Random Forest, triaged by playbook PB-01, "
        "contained with iptables."
    )

    cases = read_cases()
    blocked = containment.list_blocked()

    open_cases = (
        cases[cases["action"] != "CLOSED"] if not cases.empty else cases
    )
    high = (
        open_cases[open_cases["severity"] == "HIGH"]
        if not open_cases.empty else open_cases
    )

    # --- Header -----------------------------------------------------------
    mode, opened, severe, contained, latency = st.columns(5)

    mode.metric("Mode", config.MODE)
    opened.metric("Open cases", 0 if open_cases.empty else len(open_cases))
    severe.metric("High severity", 0 if high.empty else len(high))
    contained.metric("Blocked now", len(blocked))

    stats = read_latency()
    latency.metric(
        "Containment p95",
        f"{stats['p95']:.2f}s" if stats else "--",
        help=None if stats else "No block has been applied yet.",
    )

    if config.CONTAINMENT_DRY_RUN:
        st.warning(
            "Dry run: containment prints its commands instead of running them. "
            "Set CONTAINMENT_DRY_RUN = False on the lab VM to block for real."
        )

    st.divider()

    # --- Cases ------------------------------------------------------------
    st.subheader("Cases")

    if cases.empty:
        st.info(
            "No cases yet. Start the capture and send traffic from the "
            "attacker VM - anything the model scores above the threshold "
            "shows up here."
        )
    else:
        table = cases.copy()
        table["blocked"] = table["src_ip"].isin(blocked)
        table["probability"] = table["probability"].round(3)

        st.dataframe(
            table[[
                "case_id", "src_ip", "severity", "action", "probability",
                "alert_count", "blocked", "updated_at",
            ]],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Act on a case")
        st.caption(
            "Two overrides an analyst always keeps: release an address the "
            "model got wrong, and close an incident that is over."
        )

        if open_cases.empty:
            st.info("Every case is closed.")
        else:
            ordered = open_cases.sort_values(
                by="severity", key=lambda s: s.map(SEVERITY_ORDER).fillna(9)
            )

            for _, case in ordered.iterrows():
                label, unblock, close = st.columns([4, 1, 1])

                is_blocked = case["src_ip"] in blocked

                label.write(
                    f"**#{case['case_id']}**  {case['src_ip']}  ·  "
                    f"{case['severity']}  ·  {case['alert_count']} alerts"
                    f"{'  ·  blocked' if is_blocked else ''}"
                )

                if unblock.button(
                    "Unblock", key=f"unblock-{case['case_id']}",
                    disabled=not is_blocked,
                ):
                    containment.unblock(case["src_ip"])
                    st.success(f"Released {case['src_ip']}.")
                    st.rerun()

                if close.button("Close", key=f"close-{case['case_id']}"):
                    close_case(case["case_id"])
                    st.success(f"Closed case #{case['case_id']}.")
                    st.rerun()

    st.divider()

    # --- Alerts -----------------------------------------------------------
    st.subheader("Recent alerts")

    alerts = read_alerts()

    if alerts.empty:
        st.info("No alerts scored above the threshold yet.")
    else:
        alerts["probability"] = alerts["probability"].round(3)
        st.dataframe(alerts, use_container_width=True, hide_index=True)

    # --- Refresh ----------------------------------------------------------
    st.divider()

    if st.checkbox("Refresh automatically", value=True):
        time.sleep(REFRESH_SECONDS)
        st.rerun()
    elif st.button("Refresh now"):
        st.rerun()


if __name__ == "__main__":
    main()
