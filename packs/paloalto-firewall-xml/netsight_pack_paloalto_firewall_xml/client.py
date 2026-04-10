"""PAN-OS XML API plugin for NetSight.

Implements :class:`PanOSXMLAuthStrategy` (keygen-based authentication) and
:class:`PanOSXMLClient` (read-only operational data retrieval) for Palo Alto
Networks firewalls and Panorama running PAN-OS 6.0 or later.

Authentication model
---------------------
PAN-OS uses an API key that is generated once via a ``type=keygen`` request
and then supplied as the ``key`` query parameter on every subsequent call.
API keys do **not** support server-side revocation, so
:meth:`PanOSXMLAuthStrategy.revoke_token` is intentionally a no-op.

Supported operations
---------------------
All operations are read-only to avoid accidental configuration changes:

- ``show_system_info``  — basic device facts (hostname, model, SW version)
- ``show_interfaces``   — interface status
- ``show_routing_table`` — routing table (RIB)
- ``show_arp_table``    — ARP / neighbour table
- ``show_ha_status``    — HA state and peer information
- ``show_session_info`` — global session statistics
- ``get_traffic_logs``  — retrieve traffic log entries
- ``get_threat_logs``   — retrieve threat log entries
- ``get_system_logs``   — retrieve system log entries
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any

import requests

from netsight.auth import AuthStrategy
from netsight.base import BaseDeviceClient
from netsight.config import DeviceConfig
from netsight.exceptions import AuthenticationError, DeviceConnectionError
from netsight.output import OutputFormatter
from netsight.resilience import retry_with_backoff

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PANOS_API_PATH = "/api/"


# ---------------------------------------------------------------------------
# PanOSXMLAuthStrategy
# ---------------------------------------------------------------------------


class PanOSXMLAuthStrategy(AuthStrategy):
    """Authentication strategy for the PAN-OS XML API using keygen.

    Acquires an API key by calling ``GET /api/?type=keygen`` and parsing the
    XML response.  Because PAN-OS API keys cannot be revoked server-side,
    :meth:`revoke_token` is a deliberate no-op.

    Parameters
    ----------
    verify_ssl:
        Whether TLS certificates should be verified.  Set to ``False`` for
        self-signed certificates in lab environments.  Defaults to ``True``.
    timeout:
        Timeout in seconds for the keygen HTTP request.  Defaults to ``10``.
    """

    def __init__(self, verify_ssl: bool = True, timeout: int = 10) -> None:
        self._verify_ssl = verify_ssl
        self._timeout = timeout

    @retry_with_backoff(max_retries=3, base_delay=1.0)
    def acquire_token(self, host: str, username: str, password: str) -> str:
        """Obtain a PAN-OS API key from *host* using the given credentials.

        The key is extracted from the XML element ``//result/key`` in the
        success response.

        Parameters
        ----------
        host:
            Hostname or IP address of the PAN-OS device.
        username:
            API account username.
        password:
            API account password.  Never logged.

        Returns
        -------
        str
            The API key string.

        Raises
        ------
        AuthenticationError
            If the device responds with ``status='error'`` (bad credentials).
        DeviceConnectionError
            If the device is unreachable or the request times out.
        """
        url = f"https://{host}{_PANOS_API_PATH}"
        params = {"type": "keygen", "user": username, "password": password}

        try:
            response = requests.get(
                url,
                params=params,
                verify=self._verify_ssl,
                timeout=self._timeout,
            )
        except (ConnectionError, TimeoutError, OSError) as exc:
            logger.warning(
                "Connection failure during keygen for host=%s: %s", host, exc
            )
            raise DeviceConnectionError(
                host=host, detail=str(exc)
            ) from exc

        return self._parse_keygen_response(host, response.text)

    def revoke_token(self, host: str, token: str) -> None:
        """No-op — PAN-OS API keys do not support server-side revocation.

        Parameters
        ----------
        host:
            Ignored.
        token:
            Ignored.
        """
        # PAN-OS API keys are stateless JWTs managed by the device; there is
        # no revocation endpoint.  Callers should treat token expiry as the
        # primary invalidation mechanism.
        logger.debug(
            "revoke_token called for host=%s — PAN-OS keys are not revocable; no-op.",
            host,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_keygen_response(host: str, xml_text: str) -> str:
        """Parse the XML keygen response and extract the API key.

        Parameters
        ----------
        host:
            Used in error messages only.
        xml_text:
            Raw XML string returned by the PAN-OS API.

        Returns
        -------
        str
            The extracted API key.

        Raises
        ------
        AuthenticationError
            If the response status is not ``'success'`` or the key element is
            missing.
        """
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise AuthenticationError(
                host=host,
                detail=f"Malformed XML in keygen response: {exc}",
            ) from exc

        status = root.get("status", "")
        if status != "success":
            # Attempt to extract a message from the response for diagnostics
            msg_elem = root.find(".//msg")
            detail = msg_elem.text if msg_elem is not None else "unknown error"
            logger.warning(
                "PAN-OS keygen failed for host=%s: status=%s, detail=%s",
                host,
                status,
                detail,
            )
            raise AuthenticationError(host=host, detail=detail or "authentication failed")

        key_elem = root.find(".//result/key")
        if key_elem is None or not key_elem.text:
            raise AuthenticationError(
                host=host,
                detail="Key element missing from successful keygen response",
            )

        logger.info("PAN-OS API key acquired for host=%s", host)
        return key_elem.text


# ---------------------------------------------------------------------------
# PanOSXMLClient
# ---------------------------------------------------------------------------


class PanOSXMLClient(BaseDeviceClient):
    """NetSight device client for Palo Alto Networks PAN-OS XML API.

    All operation metadata — the set of supported operations, their
    command strings, their type (op vs log), and their log-type
    mapping — comes from the pack's ``_data/operations_catalog.toml``
    via :class:`BaseDeviceClient`'s per-instance dispatch dicts
    (``self._op_commands``, ``self._op_types``, ``self._log_types``).

    This class is deliberately free of any hardcoded operation lists,
    command strings, or log-type tables. If you need to add a new
    PAN-OS operation, edit the catalog only.

    Parameters
    ----------
    config:
        Immutable device configuration.
    auth_strategy:
        Optional :class:`PanOSXMLAuthStrategy` instance.  If omitted one is
        created automatically using ``config.verify_ssl`` and
        ``config.timeout_connect``.
    resolved_config:
        Required compiled catalog for this pack. Produced by
        :class:`netsight.config_mgmt.ConfigCompiler` or loaded from the
        cached resolved JSON by :class:`LocalBackend`. Commit 5 of the
        pack-design refactor makes this argument strictly required in
        :class:`BaseDeviceClient`; PanOSXMLClient has no fallback path.
    """

    def __init__(
        self,
        config: DeviceConfig,
        auth_strategy: PanOSXMLAuthStrategy | None = None,
        resolved_config: dict[str, Any] | None = None,
    ) -> None:
        if auth_strategy is None:
            # Resolved config connection settings take precedence over DeviceConfig
            conn = (resolved_config or {}).get("connection", {})
            auth_strategy = PanOSXMLAuthStrategy(
                verify_ssl=conn.get("verify_ssl", config.verify_ssl),
                timeout=conn.get("timeout_connect", config.timeout_connect),
            )
        super().__init__(config=config, auth_strategy=auth_strategy, resolved_config=resolved_config)

    # ------------------------------------------------------------------
    # Abstract method implementations
    # ------------------------------------------------------------------

    def _authenticate(self) -> str:
        """Obtain an API key via the auth manager's token cache.

        The keygen exchange is a pack-internal auth primitive — it is
        NOT a user-facing operation and MUST NOT appear in the catalog
        or in the allowlist. :class:`PanOSXMLAuthStrategy` handles the
        keygen HTTP request directly; this method just forwards the
        device credentials to the auth manager's token cache.

        Returns
        -------
        str
            A PAN-OS API key string.
        """
        return self._auth_manager.get_token(
            self._config.host,
            self._config.username,
            self._config.get_password(),
        )

    @retry_with_backoff(max_retries=3, base_delay=1.0)
    def _execute_raw(self, operation: str, params: Any = None) -> str:
        """Execute a PAN-OS API call and return the raw XML response text.

        Dispatch is fully data-driven from the catalog:

        * ``self._op_types[operation]`` selects between ``type=op`` and
          ``type=log`` request shapes.
        * For ``type=op`` operations, ``self._op_commands[operation]``
          supplies the XML command payload.
        * For ``type=log`` operations,
          ``self._log_types[operation]`` supplies the ``log-type``
          query-parameter value.

        Parameters
        ----------
        operation:
            The operation name. Already validated by the command gate
            and the model gate in :meth:`BaseDeviceClient.execute`.
        params:
            Optional extra query parameters merged into the request
            (e.g. ``{"nlogs": "100"}`` for log retrieval).

        Returns
        -------
        str
            Raw XML response text from the device.

        Raises
        ------
        netsight.exceptions.CommandDeniedError
            If the operation's ``type`` in the catalog is neither
            ``"op"`` nor ``"log"``. PanOSXMLClient only speaks these two
            dispatch shapes; any other type is a pack authoring error.
        """
        from netsight.exceptions import CommandDeniedError

        url = f"https://{self._config.host}{_PANOS_API_PATH}"
        request_params: dict[str, str] = {"key": self._token or ""}

        op_type = self._op_types.get(operation, "op")
        if op_type == "log":
            # Log retrieval: type=log + log-type=<catalog value>. The
            # actual log channel name (traffic/threat/system/...) comes
            # from the catalog's log_type field, populated at __init__
            # time by BaseDeviceClient.
            log_type = self._log_types.get(operation)
            if not log_type:
                raise CommandDeniedError(
                    operation=operation,
                    reason=(
                        "type='log' operation is missing a 'log_type' "
                        "field in its catalog entry"
                    ),
                )
            request_params["type"] = "log"
            request_params["log-type"] = log_type
        elif op_type == "op":
            # Operational command: type=op + cmd=<catalog XML>.
            request_params["type"] = "op"
            request_params["cmd"] = self._op_commands.get(operation, "")
        else:
            raise CommandDeniedError(
                operation=operation,
                reason=(
                    f"PanOSXMLClient does not implement dispatch for "
                    f"type={op_type!r}; supported types are 'op' and 'log'"
                ),
            )

        # Merge caller-supplied params last so they can override defaults.
        if isinstance(params, dict):
            request_params.update(params)

        logger.debug(
            "PAN-OS API GET %s op=%s type=%s params_keys=%s",
            url,
            operation,
            op_type,
            list(request_params.keys()),
        )

        conn = self._resolved.get("connection", {})
        response = requests.get(
            url,
            params=request_params,
            verify=conn.get("verify_ssl", self._config.verify_ssl),
            timeout=(
                conn.get("timeout_connect", self._config.timeout_connect),
                conn.get("timeout_read", self._config.timeout_read),
            ),
        )
        return response.text

    def get_device_info(self) -> dict:
        """Return basic device information parsed from ``show system info``.

        Executes the ``show_system_info`` operation and parses the XML
        response into a Python dict using :class:`~netsight.output.OutputFormatter`.

        Returns
        -------
        dict
            Parsed representation of the ``<response>`` element.
        """
        raw = self.execute("show_system_info")
        return OutputFormatter.to_dict(raw)

    def get_supported_operations(self) -> list[str]:
        """Return a sorted list of publicly available operations.

        The list comes from the per-instance ``_op_commands`` dict,
        which :class:`BaseDeviceClient` builds from the catalog at
        construction time. No class-level hardcoded set.

        Returns
        -------
        list[str]
            Alphabetically sorted list of operations the pack's
            compiled catalog declared.
        """
        return sorted(self._op_commands.keys())
