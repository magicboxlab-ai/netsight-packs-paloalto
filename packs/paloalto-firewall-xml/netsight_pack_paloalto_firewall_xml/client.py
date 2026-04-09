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

# Maps log-retrieval operation names to the PAN-OS log-type string.
_LOG_TYPE_MAP: dict[str, str] = {
    "get_traffic_logs": "traffic",
    "get_threat_logs": "threat",
    "get_system_logs": "system",
}


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

    All operations are read-only; write / commit operations are intentionally
    absent from :attr:`ALLOWED_OPERATIONS`.

    Parameters
    ----------
    config:
        Immutable device configuration.
    auth_strategy:
        Optional :class:`PanOSXMLAuthStrategy` instance.  If omitted one is
        created automatically using ``config.verify_ssl`` and
        ``config.timeout_connect``.
    """

    ALLOWED_OPERATIONS: set[str] = {
        "show_system_info",
        "show_interfaces",
        "show_routing_table",
        "show_arp_table",
        "show_ha_status",
        "show_session_info",
        "get_traffic_logs",
        "get_threat_logs",
        "get_system_logs",
        "keygen",
    }

    # Maps operational (non-log) operations to their PAN-OS XML op commands.
    _OP_COMMANDS: dict[str, str] = {
        "show_system_info": "<show><system><info></info></system></show>",
        "show_interfaces": "<show><interface>all</interface></show>",
        "show_routing_table": "<show><routing><route></route></routing></show>",
        "show_arp_table": "<show><arp><entry name='all'/></arp></show>",
        "show_ha_status": "<show><high-availability><state></state></high-availability></show>",
        "show_session_info": "<show><session><info></info></session></show>",
        "keygen": "",  # keygen is handled by the auth strategy, not op commands
    }

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
        super().__init__(config, auth_strategy, resolved_config=resolved_config)

    # ------------------------------------------------------------------
    # Abstract method implementations
    # ------------------------------------------------------------------

    def _authenticate(self) -> str:
        """Obtain an API key via the auth manager's token cache.

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

        Builds the appropriate ``type=op`` or ``type=log`` request based on
        the operation, then performs a GET to ``/api/``.

        Parameters
        ----------
        operation:
            Validated operation string from :attr:`ALLOWED_OPERATIONS`.
        params:
            Optional extra parameters merged into the request.  Can be a
            dict of PAN-OS query parameters (e.g. ``{"nlogs": "20"}`` for
            log retrieval).

        Returns
        -------
        str
            The raw XML text returned by the device.
        """
        url = f"https://{self._config.host}{_PANOS_API_PATH}"
        request_params: dict[str, str] = {"key": self._token or ""}

        if operation in _LOG_TYPE_MAP:
            request_params.update(self._build_log_params(operation, params))
        else:
            cmd = self._op_commands.get(operation) or self._OP_COMMANDS.get(operation, "")
            request_params["type"] = "op"
            request_params["cmd"] = cmd

        # Merge any caller-supplied params (allow overriding defaults)
        if isinstance(params, dict):
            request_params.update(params)

        logger.debug(
            "PAN-OS API GET %s op=%s params_keys=%s",
            url,
            operation,
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

    def _build_log_params(
        self, operation: str, params: Any = None
    ) -> dict[str, str]:
        """Construct PAN-OS log-query parameters for a log-retrieval operation.

        Parameters
        ----------
        operation:
            One of ``"get_traffic_logs"``, ``"get_threat_logs"``, or
            ``"get_system_logs"``.
        params:
            Optional caller-supplied dict merged into the result (e.g.
            ``{"nlogs": "100", "query": "(addr.src in 10.0.0.0/8)"}``).

        Returns
        -------
        dict[str, str]
            Parameter dict ready to merge into the full request params.
        """
        log_params: dict[str, str] = {
            "type": "log",
            "log-type": _LOG_TYPE_MAP[operation],
        }
        if isinstance(params, dict):
            log_params.update(params)
        return log_params

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

        Excludes internal operations (``keygen``) that should not be
        exposed to external callers.

        Returns
        -------
        list[str]
            Alphabetically sorted list of publicly advertised operations.
        """
        return sorted(self.ALLOWED_OPERATIONS - {"keygen"})
