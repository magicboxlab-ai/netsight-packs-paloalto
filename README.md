# netsight-packs-paloalto

Palo Alto Networks vendor packs for the [NetSight SDK](https://github.com/magicboxlab-ai/netsight).

This repo follows the per-vendor pack distribution model described in the NetSight developer guide: one repo per vendor, holding one or more packs under `packs/`, each a self-contained Python distribution with its own `pyproject.toml`, `_data/` config tree, and PyPI-compatible entry-point registration.

## Packs in this repo

| Pack | Device class | Protocol | Status |
|---|---|---|---|
| `paloalto-firewall-xml` | firewall | XML API | beta |

## Installing a pack

Each pack is installed as a git-URL dependency pointing at its subdirectory in this repo. You'll need the NetSight core installed first:

```sh
# Core SDK from PyPI
pip install netsight

# The pack from this repo
pip install git+https://github.com/magicboxlab-ai/netsight-packs-paloalto.git#subdirectory=packs/paloalto-firewall-xml
```

Pin to a specific tag for reproducibility:

```sh
pip install git+https://github.com/magicboxlab-ai/netsight-packs-paloalto.git@paloalto-firewall-xml/v0.1.0#subdirectory=packs/paloalto-firewall-xml
```

Or use NetSight's bundled pack index + install helper (the index in `netsight` core points at this repo):

```sh
netsight pack install paloalto-firewall-xml
```

## After installation

NetSight discovers installed packs via the `netsight.packs` entry-point group at startup. Verify discovery:

```sh
netsight pack list
# NAME                     VERSION  DEVICE_CLASS  PROTOCOL  STATUS
# paloalto-firewall-xml    0.1.0    firewall      xml       installed

netsight doctor
# Includes: pack discovery, pack load errors, allowlist discovery, allowlist drift
```

The pack ships a catalog of operations (`_data/operations_catalog.toml`) but **does not grant permission to run any of them**. Enable the ones you want per-user:

```sh
netsight allowlist show paloalto-firewall-xml           # see the catalog
netsight allowlist enable paloalto-firewall-xml show_system_info show_interfaces
```

## Pack authoring

This repo's packs all follow the canonical layout documented in the NetSight developer guide's "Authoring a pack" section and in the `pack_authoring` recipe exposed by the NetSight dev MCP server.

The reference implementation is `packs/paloalto-firewall-xml/`:

```
packs/paloalto-firewall-xml/
├── pyproject.toml
├── README.md
├── LICENSE
└── netsight_pack_paloalto_firewall_xml/
    ├── __init__.py                 # register() — called by netsight.packs loader
    ├── client.py                   # PanOSXMLClient (BaseDeviceClient subclass)
    ├── validator.py                # operation validator
    ├── parser_functions.py         # @function_registry decorators
    ├── py.typed                    # PEP 561 marker
    └── _data/
        ├── metadata.toml
        ├── auth.toml
        ├── operations_catalog.toml  # catalog of supported ops (NOT a permission grant)
        ├── validator_schema.toml
        ├── parsers/*.yaml           # parser specs per operation
        └── pa-vm/                   # model-level overrides
            ├── connection.toml
            └── metadata.toml
```

Adding a second pack (e.g. `paloalto-panorama-rest`) is a matter of creating a new `packs/paloalto-panorama-rest/` directory with the same shape and tagging it separately.

## Development

```sh
# Clone and install in editable mode against a local NetSight checkout
git clone https://github.com/magicboxlab-ai/netsight-packs-paloalto.git
cd netsight-packs-paloalto
pip install -e packs/paloalto-firewall-xml

# Verify
netsight pack list
```

## Versioning and release

Each pack has an independent version, tagged as `<pack-name>/v<version>` (e.g. `paloalto-firewall-xml/v0.1.0`). This lets packs in the same repo release on independent cadences. The NetSight core repo's `netsight/packs/_index.toml` records the minimum compatible core version (`min_core`) for each pack.

## License

MIT — see [LICENSE](LICENSE).
