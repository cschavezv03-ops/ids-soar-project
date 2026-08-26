"""
Containment: the only place in the system that touches the firewall.

SOAR decides, containment executes. Nothing above this module knows that
ipset or iptables exist, and nothing in this module decides whether an IP
deserves to be blocked - except for one refusal it is never allowed to skip
(see WHITELIST below).

Blocking model:

    ipset ids_blocked   holds the blocked addresses, each with its own timeout
    IDS_BLOCK           an iptables chain that DROPs anything in that set
    INPUT -> IDS_BLOCK  hooks the chain into the traffic arriving at this host

The TTL lives in the ipset, not in a Python timer. That matters: if the IDS
process dies, the kernel still expires the block on schedule. There is no such
thing as a permanent automatic block.
"""
import subprocess

from src.common import config


class ContainmentError(RuntimeError):
    """Raised when a containment operation fails."""


# Stands in for the kernel's ipset while CONTAINMENT_DRY_RUN is on, so the
# decision logic can be exercised on a normal PC without root or iptables.
_dry_run_blocked: set[str] = set()


def _run_command(command):
    """
    Execute one firewall command and return its stdout.

    In dry-run mode nothing is executed: the command is printed so the log
    still shows exactly what would have happened on the VM.
    """
    if config.CONTAINMENT_SUDO:
        command = ["sudo", "-n"] + list(command)

    if config.CONTAINMENT_DRY_RUN:
        print("[containment:dry-run]", " ".join(command))
        return ""

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    except (subprocess.CalledProcessError, OSError) as exc:
        raise ContainmentError(
            f"Containment command failed: {' '.join(command)}"
        ) from exc


def _chain_exists():
    try:
        _run_command(["iptables", "-L", config.IPTABLES_CHAIN, "-n"])
        return True
    except ContainmentError:
        return False


def _input_chain_rule_exists():
    try:
        _run_command(["iptables", "-C", "INPUT", "-j", config.IPTABLES_CHAIN])
        return True
    except ContainmentError:
        return False


def _block_rule_exists():
    try:
        _run_command([
            "iptables", "-C", config.IPTABLES_CHAIN,
            "-m", "set", "--match-set", config.IPSET_NAME, "src",
            "-j", "DROP",
        ])
        return True
    except ContainmentError:
        return False


def setup():
    """
    Build the firewall structure. Safe to call repeatedly: every step checks
    whether its object already exists, so a restart does not stack duplicate
    rules on top of the previous run.
    """
    if config.CONTAINMENT_DRY_RUN:
        print("[containment:dry-run] setup skipped (no real firewall)")
        return

    # The set carries a default timeout so an entry added without an explicit
    # one still expires.
    _run_command([
        "ipset", "create", config.IPSET_NAME, "hash:ip",
        "timeout", str(config.BLOCK_TTL_SECONDS), "-exist",
    ])

    if not _chain_exists():
        _run_command(["iptables", "-N", config.IPTABLES_CHAIN])

    if not _block_rule_exists():
        _run_command([
            "iptables", "-A", config.IPTABLES_CHAIN,
            "-m", "set", "--match-set", config.IPSET_NAME, "src",
            "-j", "DROP",
        ])

    # -I INPUT 1: the jump goes first, so a blocked address is dropped before
    # any ACCEPT rule further down the chain can let it through.
    if not _input_chain_rule_exists():
        _run_command([
            "iptables", "-I", "INPUT", "1", "-j", config.IPTABLES_CHAIN,
        ])


def block(ip, ttl):
    """
    Block one address for ttl seconds. Returns True if it was blocked,
    False if the whitelist refused it.

    The whitelist check is duplicated here on purpose. SOAR already filters
    whitelisted addresses during enrichment, but this is the last gate before
    the kernel, and it is the one that survives a future caller - the panel,
    a script, a new rule - that forgets to ask SOAR first. Blocking the
    management IP is the single most expensive mistake this system can make.
    """
    if not ip:
        raise ValueError("IP address cannot be empty")

    if ttl <= 0:
        raise ValueError("TTL must be greater than zero")

    if ip in config.WHITELIST:
        print(f"[containment] REFUSED: {ip} is whitelisted, never blocking it")
        return False

    if config.CONTAINMENT_DRY_RUN:
        _dry_run_blocked.add(ip)

    _run_command([
        "ipset", "add", config.IPSET_NAME, ip, "timeout", str(ttl), "-exist",
    ])

    print(f"[containment] BLOCKED {ip} for {ttl}s")
    return True


def unblock(ip):
    """
    Remove an address from the set - the manual human-in-the-loop override.
    Removing an address that is not there is not an error.
    """
    if not ip:
        raise ValueError("IP address cannot be empty")

    if config.CONTAINMENT_DRY_RUN:
        _dry_run_blocked.discard(ip)

    try:
        _run_command(["ipset", "del", config.IPSET_NAME, ip])
        print(f"[containment] UNBLOCKED {ip}")
    except ContainmentError:
        # Already gone, most likely expired on its own. Nothing to undo.
        return


def is_blocked(ip):
    """Whether the address is currently in the blocking set."""
    if not ip:
        raise ValueError("IP address cannot be empty")

    if config.CONTAINMENT_DRY_RUN:
        return ip in _dry_run_blocked

    try:
        _run_command(["ipset", "test", config.IPSET_NAME, ip])
        return True
    except ContainmentError:
        return False


def list_blocked():
    """Every address currently blocked. Used by the panel."""
    if config.CONTAINMENT_DRY_RUN:
        return sorted(_dry_run_blocked)

    try:
        output = _run_command(["ipset", "list", config.IPSET_NAME])
    except ContainmentError:
        return []

    addresses = []
    members = False

    for line in output.splitlines():
        if line.startswith("Members:"):
            members = True
            continue
        if members and line.strip():
            # "192.168.56.20 timeout 574" -> "192.168.56.20"
            addresses.append(line.split()[0])

    return addresses
