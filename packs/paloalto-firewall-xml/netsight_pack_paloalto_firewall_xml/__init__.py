"""NetSight pack: Palo Alto Networks firewall via PAN-OS XML API.

This package is the ``paloalto-firewall-xml`` NetSight vendor pack.  It
bundles:

- :class:`~netsight_pack_paloalto_firewall_xml.client.PanOSXMLClient` — the
  device client for PAN-OS XML API communication.
- :class:`~netsight_pack_paloalto_firewall_xml.validator.PanOSXMLOperationValidator`
  — validates that every configured operation is read-only.
- :mod:`~netsight_pack_paloalto_firewall_xml.parser_functions` — custom
  JMESPath helper functions registered at import time.
- A ``_data/`` directory that ships the parser specs and TOML configs for
  the ``pa-vm`` model variant.

The :func:`register` function is the ``netsight.packs`` entry-point
callable; it is invoked by the NetSight pack loader at startup.
"""

from __future__ import annotations

import logging
import tomllib
from importlib.metadata import PackageNotFoundError, version
from importlib.resources import files

from netsight.packs import PackInfo, PackRegistry
from netsight_pack_paloalto_firewall_xml.client import PanOSXMLClient
from netsight_pack_paloalto_firewall_xml.validator import PanOSXMLOperationValidator
from netsight_pack_paloalto_firewall_xml import parser_functions  # noqa: F401 — side-effect import

logger = logging.getLogger(__name__)

_DISTRIBUTION = "netsight-pack-paloalto-firewall-xml"
_PACK_NAME = "paloalto-firewall-xml"


def _load_catalog_operation_names() -> frozenset[str]:
    """Return the set of operation names declared in the pack's catalog.

    The pack client no longer hardcodes its operation list — the
    authoritative source is ``_data/operations_catalog.toml``. Reading
    the catalog here at registration time lets :class:`PackInfo` expose
    an ``allowed_operations`` set that stays in sync with the catalog
    without any drift window.

    Returns
    -------
    frozenset[str]
        Operation names keyed by the TOML catalog's top-level sections.
    """
    catalog_res = (
        files("netsight_pack_paloalto_firewall_xml")
        / "_data"
        / "operations_catalog.toml"
    )
    with catalog_res.open("rb") as fh:
        catalog = tomllib.load(fh)
    return frozenset(catalog.keys())


def register(registry: PackRegistry) -> None:
    """Entry point called by the NetSight pack loader at startup.

    Builds a :class:`~netsight.packs.PackInfo` record describing this
    pack and passes it to *registry*.  Importing
    :mod:`~netsight_pack_paloalto_firewall_xml.parser_functions` at module
    level (above) triggers the ``@function_registry.register`` decorators
    so the custom parser helpers are available to the parser engine before
    any operation is executed.

    Parameters
    ----------
    registry:
        The :class:`~netsight.packs.PackRegistry` singleton supplied by the
        loader.  This pack's :class:`~netsight.packs.PackInfo` is registered
        into it.
    """
    try:
        pack_version = version(_DISTRIBUTION)
    except PackageNotFoundError:
        pack_version = "0.2.0"

    info = PackInfo(
        name=_PACK_NAME,
        vendor="paloalto",
        device_type="firewall",
        protocol="xml",
        distribution=_DISTRIBUTION,
        version=pack_version,
        client_class=PanOSXMLClient,
        allowed_operations=_load_catalog_operation_names(),
        config_root=files("netsight_pack_paloalto_firewall_xml") / "_data",
        validator_class=PanOSXMLOperationValidator,
        # Version compatibility — declared per the SDK/ops split contract.
        # See netsight-sdk SEMVER.md for the public API surface and bump rules.
        min_sdk_version=">=1.0.0,<2.0.0",
        declared_plugin_api=1,
        metadata={
            "description": "Palo Alto Networks PAN-OS XML API",
            "vendor": "Palo Alto Networks",
            "api_type": "XML",
            "min_panos_version": "6.0",
        },
    )
    registry.register(info)
    logger.debug("Pack '%s' v%s registered", _PACK_NAME, pack_version)
