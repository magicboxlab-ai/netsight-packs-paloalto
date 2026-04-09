"""Custom parser functions for PAN-OS quirks.

These helpers extend the NetSight parser engine's JMESPath evaluation with
PAN-OS–specific logic.  They are registered into the global
:data:`~netsight.parsers.registry.function_registry` at import time via
:func:`_register_once`.

During the Phase 5 parallel-scaffold period both this module and the legacy
:mod:`netsight.plugins.panos_xml.parser_functions` module may be imported
in the same process.  Because both modules register functions under the same
names, a second registration would normally raise :class:`ValueError`.
:func:`_register_once` silences the duplicate silently — Phase 6 removes the
legacy module entirely, after which the guard becomes dead code.
"""

from __future__ import annotations

import jmespath

from netsight.parsers.registry import function_registry


# ---------------------------------------------------------------------------
# Idempotent registration helper
# ---------------------------------------------------------------------------


def _register_once(name: str, func: object) -> None:
    """Register *func* under *name* in ``function_registry``, skipping duplicates.

    During the Phase 5 parallel-scaffold the legacy
    :mod:`netsight.plugins.panos_xml.parser_functions` module registers the
    same names first.  Subsequent registrations from this module are silently
    ignored — both callers supply identical implementations so the skip is
    safe.

    Parameters
    ----------
    name:
        Registry key to register under.
    func:
        Callable to register.
    """
    if not function_registry.has(name):
        function_registry.register(name, func)


# ---------------------------------------------------------------------------
# PAN-OS helper functions
# ---------------------------------------------------------------------------


def panos_bool_yes(data: dict, path: str) -> bool:
    """Convert a PAN-OS ``'yes'``/``'no'`` string at *path* to a Python bool.

    Parameters
    ----------
    data:
        Parsed device response dict.
    path:
        JMESPath expression that locates the ``'yes'``/``'no'`` value.

    Returns
    -------
    bool
        ``True`` when the resolved value equals ``'yes'`` (case-insensitive),
        ``False`` for ``'no'``, missing paths, or any other value.
    """
    value = jmespath.search(path, data)
    if value is None:
        return False
    return str(value).strip().lower() == "yes"


def panos_interfaces_with_status(
    data: dict, ifnet_path: str, hw_path: str
) -> list[dict]:
    """Build an interface list by joining logical (ifnet) and physical (hw) state.

    Parameters
    ----------
    data:
        Parsed device response dict.
    ifnet_path:
        JMESPath expression resolving to the list of logical interface entries.
    hw_path:
        JMESPath expression resolving to the list of physical hardware entries.

    Returns
    -------
    list[dict]
        Each element has ``name``, ``zone``, ``ip``, and ``status`` keys.
        ``status`` is the physical link state looked up from the hardware table;
        the field is an empty string when no hardware entry exists for a given
        interface name.
    """
    ifnet_entries = jmespath.search(ifnet_path, data) or []
    hw_entries = jmespath.search(hw_path, data) or []

    if not isinstance(ifnet_entries, list):
        ifnet_entries = [ifnet_entries]
    if not isinstance(hw_entries, list):
        hw_entries = [hw_entries]

    hw_state: dict[str, str] = {}
    for hw_entry in hw_entries:
        if isinstance(hw_entry, dict):
            name = hw_entry.get("name", "")
            state = hw_entry.get("state", "")
            if name:
                hw_state[name] = state

    result = []
    for entry in ifnet_entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        result.append(
            {
                "name": name,
                "zone": entry.get("zone", "") or "",
                "ip": entry.get("ip", "") or "",
                "status": hw_state.get(name, ""),
            }
        )
    return result


# ---------------------------------------------------------------------------
# Registration — runs at module import time
# ---------------------------------------------------------------------------

_register_once("panos_bool_yes", panos_bool_yes)
_register_once("panos_interfaces_with_status", panos_interfaces_with_status)
