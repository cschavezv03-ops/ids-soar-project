import subprocess

from src.common import config


class ContainmentError(RuntimeError):
    """Error raised when a containment operation fails."""


def _run_command(command):
    """
    Execute a system command and return its standard output.
    """

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True
        )

        return result.stdout.strip()

    except (subprocess.CalledProcessError, OSError) as exc:
        raise ContainmentError(
            f"Containment command failed: {' '.join(command)}"
        ) from exc


def _chain_exists():
    """
    Check whether the IDS_BLOCK iptables chain exists.
    """

    try:
        _run_command([
            "iptables",
            "-L",
            config.IPTABLES_CHAIN,
            "-n"
        ])

        return True

    except ContainmentError:
        return False


def _input_chain_rule_exists():
    """
    Check whether INPUT already jumps to IDS_BLOCK.
    """

    try:
        _run_command([
            "iptables",
            "-C",
            "INPUT",
            "-j",
            config.IPTABLES_CHAIN
        ])

        return True

    except ContainmentError:
        return False


def _block_rule_exists():
    """
    Check whether IDS_BLOCK already contains the ipset DROP rule.
    """

    try:
        _run_command([
            "iptables",
            "-C",
            config.IPTABLES_CHAIN,
            "-m",
            "set",
            "--match-set",
            config.IPSET_NAME,
            "src",
            "-j",
            "DROP"
        ])

        return True

    except ContainmentError:
        return False


def setup():

    # Create the ipset if it does not already exist.
    _run_command([
        "ipset",
        "create",
        config.IPSET_NAME,
        "hash:ip",
        "timeout",
        str(config.BLOCK_TTL_SECONDS),
        "-exist"
    ])

    # Create the IDS_BLOCK chain if it does not already exist.
    if not _chain_exists():
        _run_command([
            "iptables",
            "-N",
            config.IPTABLES_CHAIN
        ])

    # Add the DROP rule for source IPs contained in the ipset.
    if not _block_rule_exists():
        _run_command([
            "iptables",
            "-A",
            config.IPTABLES_CHAIN,
            "-m",
            "set",
            "--match-set",
            config.IPSET_NAME,
            "src",
            "-j",
            "DROP"
        ])

    # Connect INPUT to IDS_BLOCK.
    if not _input_chain_rule_exists():
        _run_command([
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-j",
            config.IPTABLES_CHAIN
        ])


def block(ip, ttl):
    """
    Add an IP address to the blocking ipset with the given TTL.
    """

    if not ip:
        raise ValueError("IP address cannot be empty")

    if ttl <= 0:
        raise ValueError("TTL must be greater than zero")

    _run_command([
        "ipset",
        "add",
        config.IPSET_NAME,
        ip,
        "timeout",
        str(ttl),
        "-exist"
    ])


def unblock(ip):
    """
    Remove an IP address from the blocking ipset.
    """

    if not ip:
        raise ValueError("IP address cannot be empty")

    try:
        _run_command([
            "ipset",
            "del",
            config.IPSET_NAME,
            ip
        ])

    except ContainmentError:
        # The IP is already unblocked.
        return


def is_blocked(ip):
    """
    Check whether an IP address belongs to the blocking ipset.
    """

    if not ip:
        raise ValueError("IP address cannot be empty")

    try:
        _run_command([
            "ipset",
            "test",
            config.IPSET_NAME,
            ip
        ])

        return True

    except ContainmentError:
        return False