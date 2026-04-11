# Changelog

All notable changes to the paloalto packs in this repo are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

Each pack has an independent version, tagged as `<pack-name>/v<version>`.

---

## paloalto-firewall-xml

### [Unreleased]

### [0.2.0] — 2026-04-09

#### Added

- **Phase 4 — HA and logs operations (8 new operations).** All generated via
  the `netsight pack add-operation` automated pipeline and verified against a
  live PAN-OS sandbox firewall.
  - `show_ha_status` — High-availability group status and peer state
  - `show_ha_path_monitoring` — HA path monitoring destinations and status
  - `show_ha_link_monitoring` — HA link monitoring group details
  - `show_ha_counters` — HA sync and failover counters
  - `get_traffic_logs` — Traffic log retrieval (type: log)
  - `get_threat_logs` — Threat and vulnerability log retrieval (type: log)
  - `get_url_logs` — URL filtering log retrieval (type: log)
  - `get_data_logs` — Data filtering log retrieval (type: log)

- **Phase 3 — Security policy operations (9 new operations).**
  - `show_security_policy` — Active security policy rule table
  - `show_nat_policy` — NAT policy rules
  - `show_pbf_policy` — Policy-based forwarding rules
  - `show_dos_policy` — DoS protection policy rules
  - `show_qos_policy` — QoS policy rules
  - `show_address_objects` — Address and address-group objects
  - `show_service_objects` — Service and service-group objects
  - `show_application_objects` — Application objects and groups
  - `show_security_zones` — Security zone configuration

- **Phase 2 — Routing operations (10 new operations).**
  - `show_routing_summary` — Routing table summary by protocol
  - `show_bgp_summary` — BGP summary including neighbor counts and prefixes
  - `show_bgp_peers` — BGP peer status and session details
  - `show_ospf_neighbors` — OSPF neighbor adjacency state
  - `show_ospf_database` — OSPF link-state database
  - `show_rip_statistics` — RIP protocol statistics
  - `show_route_detail` — Detailed route entry for a specific prefix
  - `show_fib` — Forwarding information base
  - `show_multicast_route` — Multicast routing table
  - `show_tunnel_interfaces` — Tunnel interface status

- **Phase 1 — System and network operations (11 new operations).**
  - `show_system_resources` — CPU, memory, and disk utilization
  - `show_system_environmentals` — Hardware temperature, fan, and power state
  - `show_jobs` — Background job queue and completion status
  - `show_admins` — Active administrator sessions
  - `show_clock` — System clock and timezone
  - `show_ntp` — NTP server status and synchronization state
  - `show_dns` — DNS resolver configuration
  - `show_session_info` — Active session count and capacity
  - `show_session_meter` — Per-application session counters
  - `show_counter_global` — Global packet and byte counters
  - `show_neighbor_discovery` — IPv6 neighbor discovery cache

- **Per-operation test files** for all 48 operations in `tests/`. Each file
  uses the `resolved_config` fixture pattern from `tests/_helpers.py` and is
  validated by `test_catalog_drift.py`.

- **`test_catalog_drift.py`** — Fails the pack CI if a new operation is added
  without a matching test file, a test file references a non-existent operation,
  or the synthetic `resolved_config` fixture drifts from the real catalog.

- **`tests/_helpers.py`** — Shared fixture builder for synthetic `resolved_config`
  dicts keyed by operation name, used by all per-operation test files.

### [0.1.1] — 2026-04-07

#### Changed

- `_data/operations.toml` renamed to `_data/operations_catalog.toml` to match
  the SDK's canonical filename (no content changes).

#### Fixed

- Pack now passes `compile_dry_run` with the updated SDK that requires the
  `operations_catalog.toml` filename.

### [0.1.0] — 2026-04-06

#### Added

- Initial pack release with 10 operations:
  - `show_system_info` — System identity, model, PAN-OS version, and uptime
  - `show_interfaces` — Interface inventory, IP addresses, and link state
  - `show_routing_table` — IP routing table with next-hop and metric
  - `show_arp_table` — ARP cache with IP-to-MAC mappings
  - `show_ha_status` — High-availability group state (initial version)
  - `show_session_table` — Active session table (sample of top sessions)
  - `show_threat_stats` — Threat detection counters by category
  - `show_url_stats` — URL filtering category hit counts
  - `show_application_stats` — Top applications by bytes and session count
  - `get_system_logs` — System event log retrieval (type: log)
- Parser specs for all 10 operations in `_data/parsers/`.
- `PanOSXMLClient` (`client.py`) — catalog-driven BaseDeviceClient subclass
  for the PAN-OS XML API.
- `validator.py` — operation validator enforcing XML command structure and
  blocking destructive keywords.
- `parser_functions.py` — custom JMESPath functions for interface status
  normalization (`panos_interfaces_with_status`).
- `pyproject.toml` with `netsight.packs` entry-point declaration.
