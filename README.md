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

---

## Local AWX Demo (DevSecOps Pipeline)

This section describes the local laptop demo built to showcase the full DevSecOps automation pipeline during the defense.

### Architecture
GitHub (source) → AWX (automation UI) → Ansible → 3 local KVM VMs
├── soc-master  (192.168.122.35) k3s control-plane + Wazuh agent
├── soc-worker1 (192.168.122.10) k3s worker + Suricata + Wazuh agent
└── soc-worker2 (192.168.122.95) k3s worker + Wazuh agent
### Tools Used

| Tool | Role |
|------|------|
| Terraform + libvirt/KVM | Provisions the 3 local VMs (Infrastructure as Code) |
| AWX (Ansible Tower OSS) | Web UI for running Ansible playbooks |
| Ansible | Configures k3s, Wazuh agents, Suricata |
| kind (Kubernetes-in-Docker) | Hosts AWX locally |
| GitHub Actions | CI/CD pipeline — validates on every push |

### What is Automated

- VM provisioning via `terraform apply`
- k3s cluster installation (3-node)
- Wazuh agent installation and activation (connected to real Proxmox Wazuh manager)
- Suricata installation, rules download, and config validation

### What is Validated

- k3s: `kubectl get nodes` → 3/3 Ready
- Wazuh: `systemctl is-active wazuh-agent` → active on all nodes
- Suricata: `suricata -T` config test passes, rules file present

### How to Run Before Defense

```bash
bash ~/soc-platform/scripts/start-local-demo.sh
```

Then open AWX at **http://localhost:8080** and launch the **"Deploy LOCAL SOC Demo"** job template.

### Important Notes

- This local demo does **not** replace the real SOC platform running on Proxmox.
- The Proxmox architecture (Wazuh, TheHive, Cortex, Shuffle, Suricata) is untouched.
- Suricata is **installed and validated** in this demo. Live traffic capture is not claimed.
- The Wazuh agents connect to the **real Wazuh manager** at 172.16.10.9.
