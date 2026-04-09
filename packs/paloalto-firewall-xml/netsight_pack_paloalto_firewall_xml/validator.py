"""PAN-OS XML API operation validator.

Validates that config operations intended for PAN-OS devices:

* Use an allowed XML root element (only ``<show>`` and ``<get>`` are safe).
* Do not contain destructive root elements (``<set>``, ``<delete>``, etc.).
* For ``<request>`` operations, ensure the sub-path does not include
  destructive actions like ``restart``, ``shutdown``, ``reboot``, or
  ``clear`` (while allowing safe sub-paths like ``status``).

Design decisions
----------------
* Parsing is strict: invalid XML is always an error, even if the intent
  might be safe.  Fail-closed is the contract.
* Root-element matching is case-insensitive so that ``<Show>`` and
  ``<SHOW>`` are both handled correctly.
* The ``<request>`` path walker collects all descendant tag names so
  that deeply nested destructive tags (e.g.
  ``<request><system><restart/></system></request>``) are caught
  regardless of nesting depth.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from netsight.config_mgmt.schemas import ValidationError
from netsight.config_mgmt.validator import BaseOperationValidator


class PanOSXMLOperationValidator(BaseOperationValidator):
    """Validator for Palo Alto Networks PAN-OS XML API operations.

    Enforces a read-only, non-destructive subset of the PAN-OS XML API
    by inspecting the root element and, for ``<request>`` commands, the
    sub-element path.
    """

    # Root elements that are unconditionally safe (read-only by nature).
    _ALLOW_ROOTS: frozenset[str] = frozenset({"show", "get"})

    # Root elements that are always destructive and must be blocked.
    _BLOCK_ROOTS: frozenset[str] = frozenset(
        {"set", "delete", "edit", "rename", "move", "commit", "import", "export"}
    )

    # Sub-path tag names under <request> that indicate a destructive action.
    _BLOCK_REQUEST_PATHS: frozenset[str] = frozenset(
        {"restart", "shutdown", "reboot", "clear"}
    )

    _VALID_CATEGORIES: list[str] = ["system", "network", "security", "logs", "inventory"]
    _VALID_TYPES: list[str] = ["op", "log"]

    # ------------------------------------------------------------------
    # BaseOperationValidator interface
    # ------------------------------------------------------------------

    def get_valid_categories(self) -> list[str]:
        """Return the list of accepted operation categories."""
        return list(self._VALID_CATEGORIES)

    def get_valid_types(self) -> list[str]:
        """Return the list of accepted operation types."""
        return list(self._VALID_TYPES)

    def validate_command(
        self, operation_name: str, command: str, op_type: str
    ) -> list[ValidationError]:
        """Validate a PAN-OS XML command string for safety.

        Parameters
        ----------
        operation_name:
            Key used to build the ``field`` path in returned errors.
        command:
            Raw XML command string to validate.
        op_type:
            Operation type (``"op"`` or ``"log"``).

        Returns
        -------
        list[ValidationError]
            Empty if the command is safe; otherwise one entry per problem.
        """
        prefix = f"operations.{operation_name}"
        errors: list[ValidationError] = []

        # 1. Validate op_type first.  Even if XML is valid, an unknown
        #    type means the system would not know how to dispatch it.
        if op_type not in self._VALID_TYPES:
            errors.append(
                ValidationError(
                    field=f"{prefix}.type",
                    message=(
                        f"invalid op_type {op_type!r}; "
                        f"must be one of {sorted(self._VALID_TYPES)}"
                    ),
                )
            )
            return errors

        # 2. Log-type operations use a different request path and do not
        #    carry XML commands — skip XML validation for them.
        if op_type == "log":
            return errors

        # 3. Parse XML.  Any parse failure is a hard error.
        try:
            root = ET.fromstring(command)
        except ET.ParseError as exc:
            errors.append(
                ValidationError(
                    field=f"{prefix}.command",
                    message=f"Invalid XML: {exc}",
                )
            )
            return errors

        root_tag: str = root.tag.lower()

        # 3. Block unconditionally destructive root elements.
        if root_tag in self._BLOCK_ROOTS:
            errors.append(
                ValidationError(
                    field=f"{prefix}.command",
                    message=(
                        f"Destructive root element blocked: <{root_tag}>; "
                        "only read-only commands are permitted"
                    ),
                )
            )
            return errors

        # 4. Handle <request> commands — walk the full element path.
        if root_tag == "request":
            path_tags: set[str] = {
                elem.tag.lower() for elem in root.iter() if elem is not root
            }

            blocked: set[str] = path_tags & self._BLOCK_REQUEST_PATHS
            if blocked:
                errors.append(
                    ValidationError(
                        field=f"{prefix}.command",
                        message=(
                            f"Destructive sub-path detected in <request>: "
                            f"{sorted(blocked)}; operation blocked"
                        ),
                    )
                )
            # If no blocked paths found, the request is safe (e.g. <status>).
            return errors

        # 5. Anything not in the allow-list and not <request> is blocked.
        if root_tag not in self._ALLOW_ROOTS:
            errors.append(
                ValidationError(
                    field=f"{prefix}.command",
                    message=(
                        f"Root element <{root_tag}> not in allow list "
                        f"{sorted(self._ALLOW_ROOTS)}; command blocked"
                    ),
                )
            )

        return errors
