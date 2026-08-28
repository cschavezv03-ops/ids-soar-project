from unittest.mock import call, patch

import pytest

from src.system import containment


def test_block_executes_ipset_with_ttl():
    with patch(
        "src.system.containment._run_command"
    ) as mock_run:

        containment.block(
            "192.168.56.20",
            600
        )

        mock_run.assert_called_once_with([
            "ipset",
            "add",
            "ids_blocked",
            "192.168.56.20",
            "timeout",
            "600",
            "-exist"
        ])


def test_unblock_executes_ipset_delete():
    with patch(
        "src.system.containment._run_command"
    ) as mock_run:

        containment.unblock(
            "192.168.56.20"
        )

        mock_run.assert_called_once_with([
            "ipset",
            "del",
            "ids_blocked",
            "192.168.56.20"
        ])


def test_is_blocked_returns_true_when_ipset_test_succeeds():
    with patch(
        "src.system.containment._run_command",
        return_value=""
    ):
        assert containment.is_blocked(
            "192.168.56.20"
        ) is True


def test_is_blocked_returns_false_when_ipset_test_fails():
    with patch(
        "src.system.containment._run_command",
        side_effect=containment.ContainmentError("not found")
    ):
        assert containment.is_blocked(
            "192.168.56.20"
        ) is False


def test_block_rejects_empty_ip():
    with pytest.raises(ValueError):
        containment.block(
            "",
            600
        )


def test_block_rejects_invalid_ttl():
    with pytest.raises(ValueError):
        containment.block(
            "192.168.56.20",
            0
        )


def test_setup_creates_ipset():
    with patch(
        "src.system.containment._run_command"
    ) as mock_run:

        containment.setup()

        commands = [
            call.args[0]
            for call in mock_run.call_args_list
        ]

        assert [
            "ipset",
            "create",
            "ids_blocked",
            "hash:ip",
            "timeout",
            "600",
            "-exist"
        ] in commands

def test_setup_creates_chain_when_missing():
    with patch(
        "src.system.containment._run_command"
    ) as mock_run:

        def command_side_effect(command):
            if command == [
                "iptables",
                "-L",
                "IDS_BLOCK",
                "-n"
            ]:
                raise containment.ContainmentError(
                    "chain does not exist"
                )

            if command == [
                "iptables",
                "-C",
                "IDS_BLOCK",
                "-m",
                "set",
                "--match-set",
                "ids_blocked",
                "src",
                "-j",
                "DROP"
            ]:
                raise containment.ContainmentError(
                    "rule does not exist"
                )

            if command == [
                "iptables",
                "-C",
                "INPUT",
                "-j",
                "IDS_BLOCK"
            ]:
                raise containment.ContainmentError(
                    "rule does not exist"
                )

            return ""

        mock_run.side_effect = command_side_effect

        containment.setup()

        commands = [
            call.args[0]
            for call in mock_run.call_args_list
        ]

        assert [
            "iptables",
            "-N",
            "IDS_BLOCK"
        ] in commands

def test_setup_adds_drop_rule_when_chain_does_not_exist():
    with patch(
        "src.system.containment._run_command"
    ) as mock_run:

        def command_side_effect(command):
            if command[:3] == [
                "iptables",
                "-L",
                "IDS_BLOCK"
            ]:
                raise containment.ContainmentError(
                    "chain does not exist"
                )

            if command[:3] == [
                "iptables",
                "-C",
                "IDS_BLOCK"
            ]:
                raise containment.ContainmentError(
                    "rule does not exist"
                )

            if command[:3] == [
                "iptables",
                "-C",
                "INPUT"
            ]:
                raise containment.ContainmentError(
                    "rule does not exist"
                )

            return ""

        mock_run.side_effect = command_side_effect

        containment.setup()

        commands = [
            call.args[0]
            for call in mock_run.call_args_list
        ]

        assert [
            "iptables",
            "-A",
            "IDS_BLOCK",
            "-m",
            "set",
            "--match-set",
            "ids_blocked",
            "src",
            "-j",
            "DROP"
        ] in commands


def test_setup_connects_input_to_chain_when_rule_does_not_exist():
    with patch(
        "src.system.containment._run_command"
    ) as mock_run:

        def command_side_effect(command):
            if command[:3] == [
                "iptables",
                "-L",
                "IDS_BLOCK"
            ]:
                raise containment.ContainmentError(
                    "chain does not exist"
                )

            if command[:3] == [
                "iptables",
                "-C",
                "IDS_BLOCK"
            ]:
                raise containment.ContainmentError(
                    "rule does not exist"
                )

            if command[:3] == [
                "iptables",
                "-C",
                "INPUT"
            ]:
                raise containment.ContainmentError(
                    "rule does not exist"
                )

            return ""

        mock_run.side_effect = command_side_effect

        containment.setup()

        commands = [
            call.args[0]
            for call in mock_run.call_args_list
        ]

        assert [
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-j",
            "IDS_BLOCK"
        ] in commands