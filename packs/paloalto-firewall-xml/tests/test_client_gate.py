"""Gate enforcement tests for :class:`PanOSXMLClient`.

The command gate refuses any operation that is not in the compiled
catalog. These tests lock in that contract from the pack side so that
removing an operation from ``operations_catalog.toml`` immediately
flips a test red.
"""

from __future__ import annotations

import pytest

from netsight.exceptions import CommandDeniedError
from netsight_pack_paloalto_firewall_xml.client import PanOSXMLClient


class TestClientGateEnforcement:
    """Operations not in the catalog must be denied before any I/O occurs."""

    def test_denied_operation_raises_command_denied_error(
        self, client: PanOSXMLClient
    ) -> None:
        with pytest.raises(CommandDeniedError):
            client.execute(operation="delete_config")

    def test_denied_operation_carries_operation_name(
        self, client: PanOSXMLClient
    ) -> None:
        with pytest.raises(CommandDeniedError) as exc_info:
            client.execute(operation="rm_slash")
        assert exc_info.value.operation == "rm_slash"

    def test_empty_operation_is_denied(self, client: PanOSXMLClient) -> None:
        with pytest.raises(CommandDeniedError):
            client.execute(operation="")

    def test_commit_is_denied(self, client: PanOSXMLClient) -> None:
        """Write operations such as 'commit' must be blocked."""
        with pytest.raises(CommandDeniedError):
            client.execute(operation="commit")

    def test_set_config_is_denied(self, client: PanOSXMLClient) -> None:
        with pytest.raises(CommandDeniedError):
            client.execute(operation="set_config")


class TestGetSupportedOperations:
    """get_supported_operations returns the catalog-backed op list."""

    def test_returns_sorted_list(self, client: PanOSXMLClient) -> None:
        ops = client.get_supported_operations()
        assert ops == sorted(ops)

    def test_returns_list_type(self, client: PanOSXMLClient) -> None:
        assert isinstance(client.get_supported_operations(), list)

    def test_matches_catalog_keys(
        self, client: PanOSXMLClient, resolved_config: dict
    ) -> None:
        """The public op list must match the catalog's op keys exactly."""
        expected = set(resolved_config["operations"].keys())
        assert set(client.get_supported_operations()) == expected

    def test_excludes_keygen(self, client: PanOSXMLClient) -> None:
        """keygen is an auth primitive — never a user-facing op."""
        assert "keygen" not in client.get_supported_operations()
