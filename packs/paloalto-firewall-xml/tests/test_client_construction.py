"""Construction tests for :class:`PanOSXMLClient`."""

from __future__ import annotations

from netsight.config import DeviceConfig
from netsight_pack_paloalto_firewall_xml.client import (
    PanOSXMLAuthStrategy,
    PanOSXMLClient,
)


class TestClientConstruction:
    """PanOSXMLClient must construct correctly with and without explicit deps."""

    def test_default_strategy_is_panos_xml_auth_strategy(
        self, device_config: DeviceConfig, resolved_config: dict
    ) -> None:
        """When auth_strategy is omitted, the client creates a PanOSXMLAuthStrategy."""
        c = PanOSXMLClient(device_config, resolved_config=resolved_config)
        assert isinstance(c._auth_manager._strategy, PanOSXMLAuthStrategy)

    def test_custom_strategy_is_used(
        self,
        device_config: DeviceConfig,
        auth_strategy: PanOSXMLAuthStrategy,
        resolved_config: dict,
    ) -> None:
        c = PanOSXMLClient(
            device_config,
            auth_strategy=auth_strategy,
            resolved_config=resolved_config,
        )
        assert c._auth_manager._strategy is auth_strategy

    def test_config_is_stored(
        self,
        device_config: DeviceConfig,
        auth_strategy: PanOSXMLAuthStrategy,
        resolved_config: dict,
    ) -> None:
        c = PanOSXMLClient(
            device_config,
            auth_strategy=auth_strategy,
            resolved_config=resolved_config,
        )
        assert c._config is device_config

    def test_catalog_populates_op_commands(self, client: PanOSXMLClient) -> None:
        """Every op-type operation in the catalog is wired into _op_commands."""
        assert "show_system_info" in client._op_commands
        assert client._op_commands["show_system_info"] == (
            "<show><system><info></info></system></show>"
        )

    def test_catalog_populates_log_types(self, client: PanOSXMLClient) -> None:
        """Every log-type operation is wired into _log_types."""
        assert client._log_types["get_traffic_logs"] == "traffic"
        assert client._log_types["get_threat_logs"] == "threat"
        assert client._log_types["get_system_logs"] == "system"

    def test_no_hardcoded_allowed_operations(self) -> None:
        """PanOSXMLClient must NOT define its own ALLOWED_OPERATIONS.

        All operation metadata comes from the catalog. A hardcoded
        class attribute would re-introduce the drift this refactor
        deleted.
        """
        # The class inherits an empty set from BaseDeviceClient but
        # must never override it with its own hardcoded list.
        assert "ALLOWED_OPERATIONS" not in PanOSXMLClient.__dict__
