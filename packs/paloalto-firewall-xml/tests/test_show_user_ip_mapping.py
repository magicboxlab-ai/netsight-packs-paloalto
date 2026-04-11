"""Per-command tests for the ``show_user_ip_mapping`` operation."""

from __future__ import annotations

from typing import Callable
from unittest.mock import MagicMock

from netsight_pack_paloalto_firewall_xml.client import PanOSXMLClient

OPERATION = "show_user_ip_mapping"
EXPECTED_CMD = "<show><user><ip-user-mapping><all></all></ip-user-mapping></user></show>"


class TestShowUserIpMapping:
    def test_calls_get_once(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        mock_get.assert_called_once()

    def test_sends_type_op(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        assert mock_get.call_args[1]["params"]["type"] == "op"

    def test_sends_exact_command_xml(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        assert mock_get.call_args[1]["params"]["cmd"] == EXPECTED_CMD

    def test_sends_api_key(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        assert mock_get.call_args[1]["params"]["key"] == "TESTTOKEN"
