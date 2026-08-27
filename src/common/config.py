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
RUNTIME_MODE_FILE = "runtime_mode.txt"

#--- Capture ---

CAPTURE_INTERFACE = "enp0s3"
BPF_FILTER = "ip and (tcp or udp)"

# True on the development PC: containment prints the commands it would run and
# keeps blocked IPs in memory. False on the lab VM, where iptables is real.
CONTAINMENT_DRY_RUN = False

# iptables and ipset need root. Rather than running the whole IDS as root, the
# user gets a scoped sudoers rule for these two binaries only.
CONTAINMENT_SUDO = True

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

# --- Rate correlation: SOAR sees the attacker, the model sees one flow ---
# Thresholds measured on lab traffic (A7). Benign peaks at 300 new connections
# per IP per 10s; slowloris reaches 486, the SYN floods thousands. 400 sits in
# the gap, with margin on both sides.
RATE_WINDOW_SECONDS  = 10
RATE_FLOWS_THRESHOLD = 400

# Authentication ports get their own, much tighter rule. Benign lab traffic has
# ZERO connections to port 22, and a real login is one connection - so 10 in a
# minute cannot be a human, while hydra passes it without trying.
AUTH_PORTS          = {22}
AUTH_RATE_WINDOW    = 60
AUTH_RATE_THRESHOLD = 10