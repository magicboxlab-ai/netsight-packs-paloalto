"""Pack-internal tests for paloalto-firewall-xml.

These tests live inside the pack so that they travel with the pack
regardless of where the pack is published (in-tree during development,
or an external per-vendor repo for release). Each operation in
``_data/operations_catalog.toml`` has a dedicated test file named
``test_<operation>.py``; ``test_catalog_drift.py`` fails the build if
the two ever go out of sync.
"""
