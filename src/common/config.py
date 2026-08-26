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
