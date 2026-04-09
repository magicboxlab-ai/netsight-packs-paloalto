"""Tests for :class:`PanOSXMLAuthStrategy` (keygen) and :meth:`revoke_token`."""

from __future__ import annotations

from typing import Callable
from unittest.mock import MagicMock, patch

import pytest

from netsight.exceptions import AuthenticationError, DeviceConnectionError
from netsight_pack_paloalto_firewall_xml.client import PanOSXMLAuthStrategy


class TestAcquireTokenSuccess:
    """acquire_token returns a token when the PAN-OS API responds with success."""

    def test_returns_key_string(
        self,
        auth_strategy: PanOSXMLAuthStrategy,
        success_keygen_xml: str,
        make_mock_response: Callable[..., MagicMock],
    ) -> None:
        with patch("requests.get", return_value=make_mock_response(success_keygen_xml)):
            token = auth_strategy.acquire_token("192.0.2.10", "admin", "secret")
        assert token == "SUPERSECRETAPIKEY"

    def test_calls_correct_url(
        self,
        auth_strategy: PanOSXMLAuthStrategy,
        success_keygen_xml: str,
        make_mock_response: Callable[..., MagicMock],
    ) -> None:
        with patch(
            "requests.get", return_value=make_mock_response(success_keygen_xml)
        ) as mock_get:
            auth_strategy.acquire_token("192.168.1.1", "admin", "secret")
        assert mock_get.call_args[0][0] == "https://192.168.1.1/api/"

    def test_sends_keygen_type_param(
        self,
        auth_strategy: PanOSXMLAuthStrategy,
        success_keygen_xml: str,
        make_mock_response: Callable[..., MagicMock],
    ) -> None:
        with patch(
            "requests.get", return_value=make_mock_response(success_keygen_xml)
        ) as mock_get:
            auth_strategy.acquire_token("192.0.2.10", "admin", "secret")
        assert mock_get.call_args[1]["params"]["type"] == "keygen"

    def test_sends_username_and_password(
        self,
        auth_strategy: PanOSXMLAuthStrategy,
        success_keygen_xml: str,
        make_mock_response: Callable[..., MagicMock],
    ) -> None:
        with patch(
            "requests.get", return_value=make_mock_response(success_keygen_xml)
        ) as mock_get:
            auth_strategy.acquire_token("192.0.2.10", "myuser", "mypassword")
        params = mock_get.call_args[1]["params"]
        assert params["user"] == "myuser"
        assert params["password"] == "mypassword"

    def test_respects_verify_ssl_false(
        self,
        success_keygen_xml: str,
        make_mock_response: Callable[..., MagicMock],
    ) -> None:
        strategy = PanOSXMLAuthStrategy(verify_ssl=False)
        with patch(
            "requests.get", return_value=make_mock_response(success_keygen_xml)
        ) as mock_get:
            strategy.acquire_token("192.0.2.10", "admin", "secret")
        assert mock_get.call_args[1]["verify"] is False

    def test_respects_verify_ssl_true(
        self,
        success_keygen_xml: str,
        make_mock_response: Callable[..., MagicMock],
    ) -> None:
        strategy = PanOSXMLAuthStrategy(verify_ssl=True)
        with patch(
            "requests.get", return_value=make_mock_response(success_keygen_xml)
        ) as mock_get:
            strategy.acquire_token("192.0.2.10", "admin", "secret")
        assert mock_get.call_args[1]["verify"] is True

    def test_respects_timeout(
        self,
        success_keygen_xml: str,
        make_mock_response: Callable[..., MagicMock],
    ) -> None:
        strategy = PanOSXMLAuthStrategy(timeout=42)
        with patch(
            "requests.get", return_value=make_mock_response(success_keygen_xml)
        ) as mock_get:
            strategy.acquire_token("192.0.2.10", "admin", "secret")
        assert mock_get.call_args[1]["timeout"] == 42


class TestAcquireTokenFailure:
    """acquire_token raises AuthenticationError when the API returns an error."""

    def test_raises_authentication_error_on_error_status(
        self,
        auth_strategy: PanOSXMLAuthStrategy,
        failure_keygen_xml: str,
        make_mock_response: Callable[..., MagicMock],
    ) -> None:
        with patch(
            "requests.get", return_value=make_mock_response(failure_keygen_xml)
        ):
            with pytest.raises(AuthenticationError):
                auth_strategy.acquire_token(
                    "192.0.2.10", "admin", "wrongpassword"
                )

    def test_authentication_error_carries_host(
        self,
        auth_strategy: PanOSXMLAuthStrategy,
        failure_keygen_xml: str,
        make_mock_response: Callable[..., MagicMock],
    ) -> None:
        with patch(
            "requests.get", return_value=make_mock_response(failure_keygen_xml)
        ):
            with pytest.raises(AuthenticationError) as exc_info:
                auth_strategy.acquire_token("192.0.2.11", "admin", "bad")
        assert exc_info.value.host == "192.0.2.11"

    def test_raises_device_connection_error_on_connection_failure(
        self, auth_strategy: PanOSXMLAuthStrategy
    ) -> None:
        with patch("requests.get", side_effect=ConnectionError("refused")):
            with pytest.raises(DeviceConnectionError):
                auth_strategy.acquire_token("192.0.2.10", "admin", "secret")

    def test_raises_device_connection_error_on_timeout(
        self, auth_strategy: PanOSXMLAuthStrategy
    ) -> None:
        with patch("requests.get", side_effect=TimeoutError("timed out")):
            with pytest.raises(DeviceConnectionError):
                auth_strategy.acquire_token("192.0.2.10", "admin", "secret")

    def test_connection_error_carries_host(
        self, auth_strategy: PanOSXMLAuthStrategy
    ) -> None:
        with patch("requests.get", side_effect=ConnectionError("refused")):
            with pytest.raises(DeviceConnectionError) as exc_info:
                auth_strategy.acquire_token("192.0.2.12", "admin", "secret")
        assert exc_info.value.host == "192.0.2.12"


class TestRevokeToken:
    """revoke_token is a no-op for PAN-OS XML API keys."""

    def test_revoke_token_does_not_raise(
        self, auth_strategy: PanOSXMLAuthStrategy
    ) -> None:
        auth_strategy.revoke_token("192.0.2.10", "SOMEAPIKEY")

    def test_revoke_token_makes_no_network_call(
        self, auth_strategy: PanOSXMLAuthStrategy
    ) -> None:
        with patch("requests.get") as mock_get:
            auth_strategy.revoke_token("192.0.2.10", "SOMEAPIKEY")
        mock_get.assert_not_called()
