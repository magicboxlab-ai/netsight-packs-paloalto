# netsight-pack-paloalto-firewall-xml

NetSight vendor pack for Palo Alto Networks firewalls via the PAN-OS XML API.

## Supported devices

- PAN-OS firewalls (PA-VM and physical series)
- PAN-OS 6.0 and later

## Operations

`show_system_info`, `show_interfaces`, `show_routing_table`, `show_arp_table`,
`show_ha_status`, `show_session_info`, `get_traffic_logs`, `get_threat_logs`,
`get_system_logs`

## Install

```sh
pip install git+https://github.com/<org>/netsight-packs-paloalto.git#subdirectory=packs/paloalto-firewall-xml
```

## In-tree editable install (development)

```sh
pip install -e packs/paloalto-firewall-xml/
```
