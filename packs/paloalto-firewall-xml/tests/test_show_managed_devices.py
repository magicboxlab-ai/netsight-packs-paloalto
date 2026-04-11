"""Per-command tests for the ``show_managed_devices`` operation."""

from __future__ import annotations

from typing import Callable
from unittest.mock import MagicMock

from netsight_pack_paloalto_firewall_xml.client import PanOSXMLClient

OPERATION = "show_managed_devices"
EXPECTED_CMD = "<show><devices><all></all></devices></show>"


class TestShowManagedDevices:
    def test_calls_get_once(
        self,
        panorama_client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(panorama_client, OPERATION)
        mock_get.assert_called_once()

    def test_sends_type_op(
        self,
        panorama_client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(panorama_client, OPERATION)
        assert mock_get.call_args[1]["params"]["type"] == "op"

    def test_sends_exact_command_xml(
        self,
        panorama_client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(panorama_client, OPERATION)
        assert mock_get.call_args[1]["params"]["cmd"] == EXPECTED_CMD

    def test_sends_api_key(
        self,
        panorama_client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(panorama_client, OPERATION)
        assert mock_get.call_args[1]["params"]["key"] == "TESTTOKEN"
