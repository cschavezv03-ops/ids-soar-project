import os
import sqlite3
import subprocess
import time
from datetime import datetime
 
import pandas as pd
import streamlit as st
 
from src.common import config
from src.system import containment
 
REFRESH_SECONDS = 3
 
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
 
SEVERITY_COLOR = {
    "HIGH": "#c0392b",
    "MEDIUM": "#e67e22",
    "LOW": "#27ae60",
}
 
MODE_COLOR = {
    "monitor": "#3498db",
    "alert": "#e67e22",
    "enforce": "#c0392b",
}
 
MODES = ["monitor", "alert", "enforce"]
 
 
# ----------------------------------------------------------------------------
# Runtime mode - shared with the IDS through a small file
# ----------------------------------------------------------------------------
 
def read_mode():
    try:
        with open(config.RUNTIME_MODE_FILE) as handle:
            mode = handle.read().strip()
        if mode in MODES:
            return mode
    except (OSError, ValueError):
        pass
    return config.MODE
 
 
def write_mode(mode):
    if mode not in MODES:
        return
    with open(config.RUNTIME_MODE_FILE, "w") as handle:
        handle.write(mode)
 
 
# ----------------------------------------------------------------------------
# Data access - read only
# ----------------------------------------------------------------------------
 
def _connect():
    return sqlite3.connect(config.CASES_DB)
 
 
def read_cases():
    if not os.path.exists(config.CASES_DB):
        return pd.DataFrame()
    con = _connect()
    try:
        return pd.read_sql_query(
            "SELECT case_id, src_ip, severity, action, probability,"
            " created_at, updated_at, alert_count"
            " FROM cases ORDER BY updated_at DESC",
            con,
        )
    except Exception:
        return pd.DataFrame()
    finally:
        con.close()
 
 
def read_case_column(name):
    if not os.path.exists(config.CASES_DB):
        return {}
    con = _connect()
    try:
        rows = con.execute(f"SELECT case_id, {name} FROM cases").fetchall()
        return {r[0]: r[1] for r in rows}
    except Exception:
        return {}
    finally:
        con.close()
 
 
def read_alerts(limit=200):
    if not os.path.exists(config.CASES_DB):
        return pd.DataFrame()
    con = _connect()
    try:
        return pd.read_sql_query(
            "SELECT case_id, src_ip, probability, timestamp"
            " FROM alerts ORDER BY id DESC LIMIT ?",
            con, params=(limit,),
        )
    except Exception:
        return pd.DataFrame()
    finally:
        con.close()
 
 
def read_alerts_for_case(case_id, limit=100):
    con = _connect()
    try:
        return pd.read_sql_query(
            "SELECT probability, timestamp FROM alerts"
            " WHERE case_id = ? ORDER BY id DESC LIMIT ?",
            con, params=(case_id, limit),
        )
    except Exception:
        return pd.DataFrame()
    finally:
        con.close()
 
 
def close_case(case_id):
    con = _connect()
    con.execute("UPDATE cases SET action='CLOSED' WHERE case_id=?", (case_id,))
    con.commit()
    con.close()
 
 
def read_latency_rows():
    """Every latency record: (case_id, ip, severity, alert_count, seconds)."""
    if not os.path.exists(config.LATENCY_LOG):
        return []
    rows = []
    with open(config.LATENCY_LOG) as handle:
        for line in handle:
            parts = line.strip().split(",")
            if len(parts) == 5:
                try:
                    rows.append((parts[0], parts[1], parts[2],
                                 int(parts[3]), float(parts[4])))
                except ValueError:
                    continue
    return rows
 
 
def latency_summary(rows):
    if not rows:
        return None
    values = sorted(r[4] for r in rows)
    n = len(values)
    return {
        "n": n,
        "p50": values[min(int(n * 0.50), n - 1)],
        "p95": values[min(int(n * 0.95), n - 1)],
        "max": values[-1],
        "min": values[0],
    }
 
 
def blocked_with_ttl():
    if config.CONTAINMENT_DRY_RUN:
        return [(ip, None) for ip in containment.list_blocked()]
    try:
        cmd = ["ipset", "list", config.IPSET_NAME]
        if config.CONTAINMENT_SUDO:
            cmd = ["sudo", "-n"] + cmd
        out = subprocess.run(cmd, capture_output=True, text=True,
                             check=True).stdout
    except Exception:
        return []
    result = []
    members = False
    for line in out.splitlines():
        if line.startswith("Members:"):
            members = True
            continue
        if members and line.strip():
            parts = line.split()
            ip = parts[0]
            ttl = None
            if "timeout" in parts:
                try:
                    ttl = int(parts[parts.index("timeout") + 1])
                except (ValueError, IndexError):
                    ttl = None
            result.append((ip, ttl))
    return result
 
 
def detection_label(case_id, triggers):
    trigger = triggers.get(case_id)
    if trigger and trigger not in ("", "None", None):
        return {
            "AUTH_BRUTE_FORCE": "SOAR - port :22 rule",
            "FLOOD": "SOAR - rate rule",
        }.get(trigger, f"SOAR - {trigger}")
    return "Model"
 
 
# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------
 
def severity_badge(sev):
    color = SEVERITY_COLOR.get(sev, "#7f8c8d")
    return (f"<span style='background:{color};color:white;padding:2px 10px;"
            f"border-radius:12px;font-size:0.8em;font-weight:600'>{sev}</span>")
 
 
def main():
    st.set_page_config(page_title="IDS + SOAR", layout="wide",
                       initial_sidebar_state="collapsed")
 
    mode = read_mode()
    mode_color = MODE_COLOR.get(mode, "#7f8c8d")
 
    # --- Header ----------------------------------------------------------
    st.markdown(
        f"<div style='display:flex;align-items:center;gap:16px'>"
        f"<h1 style='margin:0'>IDS + SOAR</h1>"
        f"<span style='background:{mode_color};color:white;padding:4px 16px;"
        f"border-radius:16px;font-weight:700;letter-spacing:1px'>"
        f"MODE {mode.upper()}</span></div>",
        unsafe_allow_html=True,
    )
    st.caption("Network flows classified by a Random Forest, triaged by "
               "playbook PB-01, contained with iptables.")
 
    # --- Mode control ----------------------------------------------------
    st.markdown("**Operating mode**")
    m1, m2, m3, _ = st.columns([1, 1, 1, 4])
    if m1.button("Monitor", use_container_width=True,
                 type="primary" if mode == "monitor" else "secondary"):
        write_mode("monitor")
        st.rerun()
    if m2.button("Alert", use_container_width=True,
                 type="primary" if mode == "alert" else "secondary"):
        write_mode("alert")
        st.rerun()
    if m3.button("Enforce", use_container_width=True,
                 type="primary" if mode == "enforce" else "secondary"):
        write_mode("enforce")
        st.rerun()
    st.caption("Monitor: detect and log only. Alert: warn without touching the "
               "firewall. Enforce: block for real. The IDS picks up the change "
               "on its next decision, no restart needed.")
 
    cases = read_cases()
    triggers = read_case_column("detection")
    blocked = blocked_with_ttl()
    blocked_ips = {ip for ip, _ in blocked}
    latency_rows = read_latency_rows()
    latency = latency_summary(latency_rows)
 
    open_cases = cases[cases["action"] != "CLOSED"] if not cases.empty else cases
    high = (open_cases[open_cases["severity"] == "HIGH"]
            if not open_cases.empty else open_cases)
 
    # --- KPIs ------------------------------------------------------------
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Open cases", 0 if open_cases.empty else len(open_cases))
    k2.metric("High severity", 0 if high.empty else len(high))
    k3.metric("Blocked now", len(blocked))
    k4.metric("Containment p95",
              f"{latency['p95']:.2f}s" if latency else "-",
              help="Time from the first attack packet to the block.")
    k5.metric("Total alerts",
              0 if cases.empty else int(cases["alert_count"].sum()))
 
    if config.CONTAINMENT_DRY_RUN:
        st.warning("Dry run: containment prints its commands instead of running "
                   "them. On the real VM this banner disappears.")
 
    st.divider()
 
    left, right = st.columns([3, 2])
 
    # ================= LEFT: cases =======================================
    with left:
        st.subheader("Cases")
        if cases.empty:
            st.info("No cases yet. Send traffic from the attacker machine and "
                    "any flow scored above the threshold will show up here.")
        else:
            for _, case in cases.sort_values(
                by="severity",
                key=lambda s: s.map(SEVERITY_ORDER).fillna(9)
            ).iterrows():
                cid = case["case_id"]
                sev = case["severity"]
                is_blocked = case["src_ip"] in blocked_ips
                is_closed = case["action"] == "CLOSED"
                detected = detection_label(cid, triggers)
 
                header = (
                    f"{'[BLOCKED] ' if is_blocked else ''}"
                    f"{'[CLOSED] ' if is_closed else ''}"
                    f"#{cid} - {case['src_ip']} - {sev} - "
                    f"{detected} - {case['alert_count']} alerts"
                )
 
                with st.expander(header,
                                 expanded=(sev == "HIGH" and not is_closed)):
                    c1, c2, c3 = st.columns(3)
                    c1.markdown(f"**Severity**<br>{severity_badge(sev)}",
                                unsafe_allow_html=True)
                    c2.metric("Max probability", f"{case['probability']:.3f}")
                    c3.metric("Detection", detected)
                    st.caption(
                        f"First seen: {case['created_at']}  |  "
                        f"Last: {case['updated_at']}  |  "
                        f"State: {case['action']}"
                    )
                    ca = read_alerts_for_case(cid)
                    if not ca.empty and len(ca) > 1:
                        st.caption("Probability per alert (most recent first):")
                        st.line_chart(ca["probability"].reset_index(drop=True),
                                      height=120)
                    b1, b2, _ = st.columns([1, 1, 3])
                    if b1.button("Unblock", key=f"ub-{cid}",
                                 disabled=not is_blocked):
                        containment.unblock(case["src_ip"])
                        st.success(f"Released {case['src_ip']}.")
                        st.rerun()
                    if not is_closed and b2.button("Close case", key=f"cl-{cid}"):
                        close_case(cid)
                        st.success(f"Case #{cid} closed.")
                        st.rerun()
 
    # ================= RIGHT: firewall + feed ============================
    with right:
        st.subheader("Firewall")
        if not blocked:
            st.info("Nothing blocked right now.")
        else:
            fw = [{"IP": ip,
                   "TTL left": f"{ttl}s" if ttl is not None else "-",
                   "State": "BLOCKED"} for ip, ttl in blocked]
            st.dataframe(pd.DataFrame(fw), use_container_width=True,
                         hide_index=True)
            st.caption("Read straight from the ipset. The TTL counts down on "
                       "its own; the kernel releases the IP at zero.")
 
        st.subheader("Live alert feed")
        alerts = read_alerts(limit=15)
        if alerts.empty:
            st.info("No alerts above the threshold yet.")
        else:
            feed = alerts.copy()
            feed["probability"] = feed["probability"].round(3)
            feed = feed.rename(columns={
                "src_ip": "Source", "probability": "Prob",
                "timestamp": "Time", "case_id": "Case",
            })
            st.dataframe(feed[["Time", "Source", "Prob", "Case"]],
                         use_container_width=True, hide_index=True, height=300)
 
    # ================= Latency section ===================================
    st.divider()
    st.subheader("Containment latency")
 
    if not latency_rows:
        st.info("No blocks recorded yet. Run an attack in enforce mode to "
                "measure the response time.")
    else:
        l1, l2, l3, l4 = st.columns(4)
        l1.metric("Blocks measured", latency["n"])
        l2.metric("Median (p50)", f"{latency['p50']:.2f}s")
        l3.metric("p95", f"{latency['p95']:.2f}s")
        l4.metric("Fastest", f"{latency['min']:.2f}s")
 
        st.caption("Time from the first packet of each incident to the block "
                   "being applied (MTTR).")
 
        table = pd.DataFrame(
            [{"Case": r[0], "IP": r[1], "Severity": r[2],
              "Alerts": r[3], "Seconds": round(r[4], 3)}
             for r in latency_rows]
        )
        st.dataframe(table, use_container_width=True, hide_index=True)
 
    # --- footer ----------------------------------------------------------
    st.divider()
    f1, f2 = st.columns([1, 4])
    auto = f1.checkbox("Auto", value=True)
    f2.caption(f"Refresh every {REFRESH_SECONDS}s  |  "
               f"last update {datetime.now().strftime('%H:%M:%S')}")
 
    if auto:
        time.sleep(REFRESH_SECONDS)
        st.rerun()
 
 
if __name__ == "__main__":
    main()
 