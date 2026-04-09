"""Shared pytest fixtures for the paloalto-firewall-xml pack tests.

The fixtures here hand-roll the same ``resolved_config`` dict shape that
``netsight.config_mgmt.ConfigCompiler`` produces when it compiles the
pack's ``operations_catalog.toml``. Keeping them in one place lets every
per-command test focus on a single command's dispatch without restating
the full catalog.

All shared XML strings and helper callables are exposed as pytest
fixtures (``success_keygen_xml``, ``run_operation``, etc.) rather than
as plain module-level constants. That keeps every test file free of
imports from sibling modules, which avoids Pyright's inability to
resolve relative imports across the pack/tests boundary.

If you add a new operation to ``_data/operations_catalog.toml``, update
:func:`resolved_config` here so every command has a fixture entry, then
add a matching ``test_<operation>.py`` file (see the other
``test_<name>.py`` files in this directory for the canonical shape).
The drift check in ``test_catalog_drift.py`` enforces both halves.
"""

from __future__ import annotations

from typing import Any, Callable
from unittest.mock import MagicMock, patch

import pytest

from netsight.config import DeviceConfig
from netsight_pack_paloalto_firewall_xml.client import (
    PanOSXMLAuthStrategy,
    PanOSXMLClient,
)

# ---------------------------------------------------------------------------
# Internal module-level constants (not fixtures; used by fixtures below).
# ---------------------------------------------------------------------------

_SUCCESS_KEYGEN_XML = (
    "<response status='success'>"
    "<result><key>SUPERSECRETAPIKEY</key></result>"
    "</response>"
)

_FAILURE_KEYGEN_XML = (
    "<response status='error'>"
    "<result><msg>Invalid credentials.</msg></result>"
    "</response>"
)

_SYSTEM_INFO_XML = """
<response status="success">
  <result>
    <system>
      <hostname>pa-vm-01</hostname>
      <model>PA-VM</model>
      <serial>unknown</serial>
      <sw-version>10.1.0</sw-version>
    </system>
  </result>
</response>
"""

_EMPTY_SUCCESS_XML = "<response status='success'><result/></response>"


def _make_mock_response(text: str, status_code: int = 200) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.text = text
    mock_resp.status_code = status_code
    return mock_resp


def _sample_config(**overrides: object) -> DeviceConfig:
    base: dict[str, object] = {
        "name": "test-fw-01",
        "api_type": "panos_xml",
        "host": "192.0.2.10",
        "username": "admin",
        "password_env": "TEST_FW01_PASSWORD",
        "verify_ssl": False,
        "timeout_connect": 5,
        "timeout_read": 10,
        "rate_limit": 10,
    }
    base.update(overrides)
    return DeviceConfig.from_dict(base)


# ---------------------------------------------------------------------------
# Environment + config fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def set_password_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide a deterministic password for tests that construct DeviceConfig."""
    monkeypatch.setenv("TEST_FW01_PASSWORD", "test_password_123")


@pytest.fixture()
def auth_strategy() -> PanOSXMLAuthStrategy:
    return PanOSXMLAuthStrategy(verify_ssl=False, timeout=5)


@pytest.fixture()
def device_config() -> DeviceConfig:
    return _sample_config()


@pytest.fixture()
def resolved_config() -> dict:
    """Synthetic ``resolved_config`` mirroring the pack's operations catalog.

    Must stay in sync with
    ``netsight_pack_paloalto_firewall_xml/_data/operations_catalog.toml``.
    The drift-prevention test in ``test_catalog_drift.py`` fails the
    build if the two go out of sync.
    """
    return {
        "connection": {},
        "auth": {},
        "resilience": {"rate_limit": 1000},  # effectively unlimited
        "metadata": {},
        "operations": {
            "show_system_info": {
                "command": "<show><system><info></info></system></show>",
                "type": "op",
                "required_model": "*",
                "category": "system",
                "description": "Show system information and uptime",
                "read_only": True,
            },
            "show_interfaces": {
                "command": "<show><interface>all</interface></show>",
                "type": "op",
                "required_model": "*",
                "category": "network",
                "description": "Show all interface status",
                "read_only": True,
            },
            "show_routing_table": {
                "command": "<show><routing><route></route></routing></show>",
                "type": "op",
                "required_model": "*",
                "category": "network",
                "description": "Show routing table",
                "read_only": True,
            },
            "show_arp_table": {
                "command": "<show><arp><entry name='all'></entry></arp></show>",
                "type": "op",
                "required_model": "*",
                "category": "network",
                "description": "Show ARP table",
                "read_only": True,
            },
            "show_ha_status": {
                "command": "<show><high-availability><all></all></high-availability></show>",
                "type": "op",
                "required_model": "*",
                "category": "system",
                "description": "Show HA status",
                "read_only": True,
            },
            "show_session_info": {
                "command": "<show><session><info></info></session></show>",
                "type": "op",
                "required_model": "*",
                "category": "system",
                "description": "Show session information",
                "read_only": True,
            },
            "get_traffic_logs": {
                "command": "",
                "type": "log",
                "log_type": "traffic",
                "required_model": "*",
                "category": "logs",
                "description": "Query traffic logs",
                "read_only": True,
            },
            "get_threat_logs": {
                "command": "",
                "type": "log",
                "log_type": "threat",
                "required_model": "*",
                "category": "logs",
                "description": "Query threat logs",
                "read_only": True,
            },
            "get_system_logs": {
                "command": "",
                "type": "log",
                "log_type": "system",
                "required_model": "*",
                "category": "logs",
                "description": "Query system logs",
                "read_only": True,
            },
            "request_logging_service_forwarding_status": {
                "command": "<request><logging-service-forwarding><status></status></logging-service-forwarding></request>",
                "type": "op",
                "required_model": "*",
                "category": "system",
                "description": "Check logging service forwarding status",
                "read_only": True,
            },
        },
    }


@pytest.fixture()
def client(
    device_config: DeviceConfig, resolved_config: dict
) -> PanOSXMLClient:
    """A fully-wired :class:`PanOSXMLClient` backed by the synthetic catalog."""
    strategy = PanOSXMLAuthStrategy(verify_ssl=False, timeout=5)
    return PanOSXMLClient(
        device_config,
        auth_strategy=strategy,
        resolved_config=resolved_config,
    )


# ---------------------------------------------------------------------------
# Shared XML / helper fixtures — exposed as fixtures (not imports) so that
# per-command test files can stay import-free and Pyright has nothing to
# complain about.
# ---------------------------------------------------------------------------


@pytest.fixture()
def success_keygen_xml() -> str:
    return _SUCCESS_KEYGEN_XML


@pytest.fixture()
def failure_keygen_xml() -> str:
    return _FAILURE_KEYGEN_XML


@pytest.fixture()
def system_info_xml() -> str:
    return _SYSTEM_INFO_XML


@pytest.fixture()
def empty_success_xml() -> str:
    return _EMPTY_SUCCESS_XML


@pytest.fixture()
def make_mock_response() -> Callable[..., MagicMock]:
    """Return the helper that builds a mock of :class:`requests.Response`."""
    return _make_mock_response


@pytest.fixture()
def run_operation() -> Callable[..., tuple[str, MagicMock]]:
    """Return a helper that executes an operation with ``requests.get`` mocked.

    The returned callable has the signature
    ``(client, operation, response_text=<empty success>, params=None) -> (result, mock_get)``.
    It pre-seeds ``client._token`` with a sentinel so the real auth
    strategy is bypassed, then patches ``requests.get`` to return a
    mock whose ``.text`` attribute equals ``response_text``.
    """

    def _run(
        client: PanOSXMLClient,
        operation: str,
        response_text: str = _EMPTY_SUCCESS_XML,
        params: Any = None,
    ) -> tuple[str, MagicMock]:
        client._token = "TESTTOKEN"
        mock_resp = _make_mock_response(response_text)
        with patch("requests.get", return_value=mock_resp) as mock_get:
            result = client.execute(operation, params)
        return result, mock_get

    return _run
