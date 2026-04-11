"""Per-command tests for the ``show_system_info`` operation.

Locks in the contract that ``client.execute(operation="show_system_info")``:

* issues a single ``GET https://<host>/api/``
* sends ``type=op`` and the exact ``cmd`` XML declared by the catalog
* forwards the cached API key as the ``key`` query parameter
* returns the raw response body unchanged
"""

from __future__ import annotations

from typing import Callable
from unittest.mock import MagicMock

from netsight_pack_paloalto_firewall_xml.client import PanOSXMLClient

OPERATION = "show_system_info"
EXPECTED_CMD = "<show><system><info></info></system></show>"


class TestShowSystemInfo:
    def test_calls_get_once(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        mock_get.assert_called_once()

    def test_uses_correct_api_url(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
    ) -> None:
        _, mock_get = run_operation(client, OPERATION)
        assert mock_get.call_args[0][0] == f"https://{client._config.host}/api/"

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

    def test_returns_response_text(
        self,
        client: PanOSXMLClient,
        run_operation: Callable[..., tuple[str, MagicMock]],
        system_info_xml: str,
    ) -> None:
        result, _ = run_operation(client, OPERATION, response_text=system_info_xml)
        assert result == system_info_xml

    def test_get_device_info_returns_dict(
        self,
        client: PanOSXMLClient,
        system_info_xml: str,
    ) -> None:
        """get_device_info() parses the response into a dict."""
        from unittest.mock import patch

        client._token = "TESTTOKEN"
        mock_resp = MagicMock()
        mock_resp.text = system_info_xml
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            info = client.get_device_info()
        assert isinstance(info, dict)
        assert "response" in info
