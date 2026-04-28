# Cloud-native Open-source SOC Platform — ESPRIT PFE 2026

A fully automated Security Operations Center (SOC) platform built on Kubernetes (k3s), deployed on Proxmox VE.

## Stack
- **SIEM/EDR**: Wazuh 4.14.3
- **NDR**: Suricata (Emerging Threats Open ruleset)
- **Indexer**: OpenSearch (via Wazuh indexer)
- **Incident Management**: TheHive 5.2.8
- **Infrastructure**: k3s on Proxmox VE, ZFS storage
- **Automation**: Ansible + GitHub Actions

## Architecture
- Master node: 172.16.10.9
- Worker1: 172.16.10.5
- Worker2: 172.16.10.10
- Agents: ubunttest (172.16.10.11), windows-soc (172.16.10.12)

## Quick Deploy
```bash
./scripts/deploy-all.sh
```

## Validation
```bash
./scripts/validate.sh
```

## Detection Scenarios
1. SSH brute force → rule 100100 → Active Response (firewall-drop) → TheHive case
2. Windows failed login → Event 4625 → Wazuh alert → TheHive case
3. Sysmon process detection → MITRE T1087/T1059 → Wazuh alert

## Compliance
See [docs/compliance-mapping.md](docs/compliance-mapping.md) for ISO 27001 mappings.
