# Local AWX Demo — Defense Explanation
## ESPRIT PFE 2026 — Ismail Triki

---

## What I Built Locally

To demonstrate the full DevSecOps automation pipeline, I built a local demo
on my laptop that reproduces the provisioning and configuration workflow
used in the real Proxmox production environment.

---

## The Pipeline (left to right)
Developer pushes code
↓
GitHub Actions (CI/CD)
validates Ansible syntax
↓
Terraform (IaC)
provisions 3 KVM VMs
on local machine
↓
AWX (Ansible Tower OSS)
pulls playbook from GitHub
runs job via web UI
↓
Ansible configures VMs:

k3s cluster (3 nodes)
Wazuh agents
Suricata NIDS
↓
Verification:
k3s Ready / Wazuh active / Suricata validated
---

## What is Real vs What is Demo

| Component | Status | Notes |
|-----------|--------|-------|
| Terraform VM provisioning | ✅ Real | Actually creates KVM VMs |
| AWX automation UI | ✅ Real | Running locally via kind |
| GitHub → AWX sync | ✅ Real | AWX pulls from real GitHub repo |
| Ansible k3s install | ✅ Real | k3s actually runs on 3 VMs |
| Wazuh agents | ✅ Real | Connected to real Proxmox manager |
| Suricata install + validation | ✅ Real | Installed, rules present, config tested |
| Suricata live capture | ⚠️ Not claimed | Validated only in this VM lab context |
| Full SOC stack (TheHive, Cortex, Shuffle) | ✅ Real | Running on Proxmox, shown separately |

---

## Why Proxmox Architecture Was Not Touched

The production SOC platform on Proxmox is stable and working with:
- 847+ TheHive cases
- 762,952+ Suricata alerts
- 5/5 Wazuh agents active
- End-to-end detection in < 4 seconds

Modifying it before the defense would risk breaking a working system.
The local demo proves the automation pipeline independently.

---

## What This Proves to the Jury

1. **Infrastructure as Code** — Terraform describes and provisions infrastructure
2. **GitOps** — AWX always pulls from GitHub, single source of truth
3. **CI/CD** — GitHub Actions validates every push automatically
4. **Configuration Management** — Ansible idempotently configures all nodes
5. **Security Tooling** — Wazuh + Suricata deployed automatically, not manually
6. **Reproducibility** — From zero to running cluster in one AWX job launch

---

## One-liner Summary for the Jury

> "I push code to GitHub, GitHub Actions validates it, Terraform provisions
> the infrastructure, and AWX runs the Ansible playbook that configures
> the full SOC stack — automatically, reproducibly, and auditably."

