# Shared parameters for A and B. One place so the two stay in sync.

# --- Lab network ---
VICTIM_IP   = "192.168.56.10"
ATTACKER_IP = "192.168.56.20"
GATEWAY_IP  = "192.168.56.1"
WHITELIST   = {"192.168.56.1", "192.168.56.10"}   # never block these

# --- Model / decision ---
# Recalibrated in A7 against 12,029 real lab benign flows. The A6 values
# (0.70 / 0.90) were fixed on CICIDS2017 alone and detected 0.6% of our own
# port scan; 0.50 detects 57%. HIGH is 0.70 because no lab attack flow ever
# reaches 0.90, so a band at 0.90 would be dead on our network.
# Evidence: contract/A7_lab_calibration_note.md, scripts_output/recalibration_report.txt
THRESHOLD   = 0.50    # min prob to treat as attack
SEV_MEDIUM  = 0.50    # severity band boundaries
SEV_HIGH    = 0.70

# --- Flow assembly ---
ACTIVE_TIMEOUT = 120  # seconds
IDLE_TIMEOUT   = 15
WINDOW_SIZE = 100 

# --- Firewall / containment ---
IPTABLES_CHAIN    = "IDS_BLOCK"
IPSET_NAME        = "ids_blocked"
BLOCK_TTL_SECONDS = 600   # high severity: 10 min
SHORT_BLOCK_TTL   = 300   # medium severity: 5 min

# --- Storage / runtime ---
CASES_DB = "cases.db"
MODE     = "monitor"   # monitor | alert | enforce

#--- Capture ---

CAPTURE_INTERFACE = None
BPF_FILTER = "ip and (tcp or udp)"

# True on the development PC: containment prints the commands it would run and
# keeps blocked IPs in memory. False on the lab VM, where iptables is real.
CONTAINMENT_DRY_RUN = True

# iptables and ipset need root. Rather than running the whole IDS as root, the
# user gets a scoped sudoers rule for these two binaries only.
CONTAINMENT_SUDO = False

# Severity is probability AND context, never probability alone. One mid-
# confidence flow is LOW; the same IP producing several is MEDIUM; a sustained
# burst is HIGH. This is what lets a slow port scan - 88 flows around 0.57,
# none of them individually above SEV_HIGH - still reach HIGH severity.
ESCALATE_TO_MEDIUM = 3     # alerts from one IP
ESCALATE_TO_HIGH   = 10

# A case with no alert for this long is over. The next alert from that IP opens
# a fresh case instead of inheriting the old worst probability forever.
CASE_TTL_SECONDS = 900

# Containment latency, one line per block: case, ip, severity, alerts, seconds.
LATENCY_LOG = "latency.csv"