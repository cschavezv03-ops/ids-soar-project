# Shared parameters for A and B. One place so the two stay in sync.

# --- Lab network ---
VICTIM_IP   = "192.168.56.10"
ATTACKER_IP = "192.168.56.20"
GATEWAY_IP  = "192.168.56.1"
WHITELIST   = {"192.168.56.1", "192.168.56.10"}   # never block these

# --- Model / decision ---
THRESHOLD   = 0.70    # min prob to treat as attack; Person A tunes after calibration
SEV_MEDIUM  = 0.70    # severity band boundaries
SEV_HIGH    = 0.90

# --- Flow assembly ---
ACTIVE_TIMEOUT = 120  # seconds
IDLE_TIMEOUT   = 15

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
