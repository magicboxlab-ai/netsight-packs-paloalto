"""Per-command tests for the ``get_traffic_logs`` operation.

This is a ``type=log`` operation — the catalog sets
``log_type = "traffic"``, which must flow through to the HTTP request
as ``log-type=traffic`` alongside ``type=log``.
"""

from __future__ import annotations

from typing import Callable
from unittest.mock import MagicMock

from netsight_pack_paloalto_firewall_xml.client import PanOSXMLClient

OPERATION = "get_traffic_logs"
EXPECTED_LOG_TYPE = "traffic"


class TestGetTrafficLogs:
    def test_calls_get_once(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        mock_get.assert_called_once()

    def test_sends_type_log(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        assert mock_get.call_args[1]["params"]["type"] == "log"

    def test_sends_log_type_traffic(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        assert mock_get.call_args[1]["params"]["log-type"] == EXPECTED_LOG_TYPE

    def test_does_not_send_cmd_param(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        """Log-type operations must not include a ``cmd`` parameter."""
        _, mock_get = run_operation(client, OPERATION)
        assert "cmd" not in mock_get.call_args[1]["params"]

    def test_sends_api_key(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        assert mock_get.call_args[1]["params"]["key"] == "TESTTOKEN"

    def test_forwards_extra_params(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        """Caller-supplied params (e.g. ``nlogs``) are merged into the request."""
        _, mock_get = run_operation(client, OPERATION, params={"nlogs": "100"})
        assert mock_get.call_args[1]["params"]["nlogs"] == "100"
