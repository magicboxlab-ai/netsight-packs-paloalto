"""Drift-prevention tests for the paloalto-firewall-xml pack.

These tests fail the build when:

1. A new operation is added to ``_data/operations_catalog.toml`` but the
   developer forgets to add a matching ``test_<operation>.py`` file.
2. The synthetic ``resolved_config`` fixture in ``conftest.py`` goes out
   of sync with the real catalog (different keys, different command
   strings, different log_type values).

The point of splitting per-command tests into one-file-per-op is that
this gate becomes meaningful: you cannot merge an operation without
also merging a test for it. Do NOT weaken these tests when adding new
operations — add the missing test file instead.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

# Locate the pack root and the catalog file deterministically, independent
# of where pytest is invoked from.
_PACK_ROOT = Path(__file__).resolve().parent.parent
_CATALOG_PATH = (
    _PACK_ROOT
    / "netsight_pack_paloalto_firewall_xml"
    / "_data"
    / "operations_catalog.toml"
)
_TESTS_DIR = _PACK_ROOT / "tests"


def _load_catalog() -> dict:
    with _CATALOG_PATH.open("rb") as fh:
        return tomllib.load(fh)


class TestCatalogTestCoverage:
    """Every catalog operation must have a dedicated test file."""

    def test_catalog_file_exists(self) -> None:
        assert _CATALOG_PATH.is_file(), f"Catalog not found at {_CATALOG_PATH}"

    def test_every_operation_has_a_test_file(self) -> None:
        """``test_<op>.py`` must exist for every operation in the catalog."""
        catalog = _load_catalog()
        missing: list[str] = []
        for op_name in catalog:
            test_file = _TESTS_DIR / f"test_{op_name}.py"
            if not test_file.is_file():
                missing.append(f"{op_name} → expected {test_file.name}")
        assert not missing, (
            "Catalog operations without dedicated test files: " + ", ".join(missing)
        )

    def test_every_test_file_matches_a_catalog_operation(self) -> None:
        """Every ``test_<op>.py`` filename must correspond to a real operation.

        This catches stale test files left behind after an operation is
        removed from the catalog — without this check, orphaned tests
        would keep passing against a command that no longer exists.
        """
        catalog = _load_catalog()
        catalog_ops = set(catalog.keys())

        # Fixed-purpose test files that are not per-command.
        non_op_tests = {
            "test_auth_strategy",
            "test_client_construction",
            "test_client_gate",
            "test_catalog_drift",
        }

        orphans: list[str] = []
        for path in _TESTS_DIR.glob("test_*.py"):
            stem = path.stem
            if stem in non_op_tests:
                continue
            # Strip the leading "test_" and check against the catalog.
            op_name = stem.removeprefix("test_")
            if op_name not in catalog_ops:
                orphans.append(stem)
        assert not orphans, (
            "Test files with no matching catalog operation: " + ", ".join(orphans)
        )


class TestCatalogFixtureSync:
    """The ``resolved_config`` fixture must mirror the real catalog."""

    def test_fixture_has_all_catalog_operations(
        self, resolved_config: dict
    ) -> None:
        catalog = _load_catalog()
        fixture_ops = set(resolved_config["operations"].keys())
        catalog_ops = set(catalog.keys())
        missing_in_fixture = catalog_ops - fixture_ops
        assert not missing_in_fixture, (
            "Operations in catalog but not in conftest.resolved_config fixture: "
            + ", ".join(sorted(missing_in_fixture))
        )

    def test_fixture_has_no_extra_operations(
        self, resolved_config: dict
    ) -> None:
        catalog = _load_catalog()
        fixture_ops = set(resolved_config["operations"].keys())
        catalog_ops = set(catalog.keys())
        extras = fixture_ops - catalog_ops
        assert not extras, (
            "Fixture has operations not in the real catalog: "
            + ", ".join(sorted(extras))
        )

    @pytest.mark.parametrize("field", ["command", "type", "required_model"])
    def test_fixture_fields_match_catalog(
        self, resolved_config: dict, field: str
    ) -> None:
        """For every op, the fixture's ``command``/``type``/``required_model`` match."""
        catalog = _load_catalog()
        mismatches: list[str] = []
        for op_name, catalog_entry in catalog.items():
            fixture_entry = resolved_config["operations"].get(op_name, {})
            expected = catalog_entry.get(field)
            actual = fixture_entry.get(field)
            if expected != actual:
                mismatches.append(
                    f"{op_name}.{field}: catalog={expected!r} "
                    f"fixture={actual!r}"
                )
        assert not mismatches, (
            f"Fixture {field} mismatches with catalog: " + "; ".join(mismatches)
        )

    def test_log_operations_fixture_log_type_matches_catalog(
        self, resolved_config: dict
    ) -> None:
        """``log_type`` is only present on log ops but must match exactly."""
        catalog = _load_catalog()
        mismatches: list[str] = []
        for op_name, catalog_entry in catalog.items():
            if catalog_entry.get("type") != "log":
                continue
            expected = catalog_entry.get("log_type")
            actual = resolved_config["operations"][op_name].get("log_type")
            if expected != actual:
                mismatches.append(
                    f"{op_name}: catalog log_type={expected!r} "
                    f"fixture log_type={actual!r}"
                )
        assert not mismatches, (
            "Fixture log_type mismatches with catalog: " + "; ".join(mismatches)
        )
