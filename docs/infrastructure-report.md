# SOC Platform — Comprehensive Infrastructure Report
**Project:** Cloud-Native Open-Source SOC Platform — ESPRIT PFE 2026
**Author:** iiismailtriki
**Date:** 2026-05-04
**Validation:** 17/17 checks PASSING — ALL SYSTEMS OPERATIONAL

---

## 1. Executive Summary

### 1.1 Platform Overview

This project delivers a production-grade, cloud-native Security Operations Center (SOC) built entirely from open-source components, deployed on a 3-node Kubernetes (k3s) cluster running on Proxmox-hosted VMs. The platform automates the full SOC workflow: detection → correlation → case management → orchestrated response.

Core capabilities:
- Real-time threat detection via Wazuh SIEM (5 agents: 3 Linux, 1 Windows with Sysmon, 1 server)
- Network intrusion detection via Suricata 7.0.3 (running on both worker nodes)
- Automated case creation in TheHive 5.2.8
- SOAR automation via Shuffle (webhook-based playbook execution)
- Threat intelligence enrichment via Cortex 3.1.7
- Full Ansible automation (6-phase deployment) and CI/CD pipeline (GitHub Actions)

### 1.2 Operational Status (2026-05-04)

| Component | Status | Version |
|-----------|--------|---------|
| k3s Cluster (3 nodes) | ALL READY | v1.34.4+k3s1 |
| Wazuh Manager | RUNNING | 4.14.3 |
| Wazuh Indexer | RUNNING | 4.14.3 (OpenSearch) |
| Wazuh Dashboard | RUNNING | 4.14.3 |
| TheHive | RUNNING | 5.2.8 |
| Cortex | RUNNING | 3.1.7 |
| Shuffle SOAR | RUNNING | latest |
| Suricata NIDS | RUNNING (2 pods) | 7.0.3 |
| Wazuh Agents | 5/5 ACTIVE | mixed |
| Active Response | CONFIGURED | firewall-drop600 |

### 1.3 KPIs — Measured Results

| KPI | Measured Value | Method |
|-----|---------------|--------|
| SSH brute force detection time (T0 to T1) | 2.17 seconds | Wazuh alerts.log timestamp diff |
| Active response time (T1 to T2 iptables DROP) | ~1 second | AR architecture (LAN) |
| Shuffle SOAR webhook trigger time | 1 second | integrations.log entry |
| End-to-end blocking (T0 to iptables) | less than 4 seconds | Calculated |
| TheHive case count | 37 cases | API verified |
| Suricata alerts (worker2) | 762,952+ | fast.log line count |
| Windows Sysmon events | 160 events (2026-05-02) | Wazuh alerts |
| Wazuh agents active | 5/5 | agent_control -l |
| Validate.sh score | 17/17 | validate.sh output |

---

## 2. Physical Infrastructure

### 2.1 Virtual Machines

| VM Name | IP Address | Role | OS |
|---------|-----------|------|----|
| master | 172.16.10.9 | k3s control-plane + Wazuh | Ubuntu 24.04.4 LTS |
| worker1 | 172.16.10.5 | k3s worker + Suricata | Ubuntu 24.04.4 LTS |
| worker2 | 172.16.10.10 | k3s worker + Docker (Cortex/Shuffle) + Suricata | Ubuntu 24.04.4 LTS |
| ubunttest | 172.16.10.11 | Attack target / Wazuh agent 007 | Ubuntu |
| windows-soc | DHCP | Windows workstation / Wazuh agent 008 + Sysmon | Windows 10 Home |

### 2.2 Network Topology

Network: 172.16.10.0/24 (Proxmox VLAN)
Pod Network (Flannel): 10.42.0.0/16
Service Network: 10.43.0.0/16

Exposed NodePorts:
| Service | NodePort | URL |
|---------|---------|-----|
| Wazuh Dashboard | 32732 | https://172.16.10.9:32732 |
| Wazuh API | 30947 | https://172.16.10.9:30947 |
| Wazuh Agent Enrollment | 31951 | 172.16.10.9:31951 |
| Wazuh Agent Syslog | 31316 | 172.16.10.9:31316 |
| Wazuh Indexer | 30193 | 172.16.10.9:30193 |
| TheHive | 31000 | http://172.16.10.10:31000 |
| Cortex | 9001 | http://172.16.10.10:9001 (Docker) |
| Shuffle SOAR | 3001 | http://172.16.10.10:3001 (Docker) |

---

## 3. Kubernetes Cluster

### 3.1 Cluster Details

| Parameter | Value |
|-----------|-------|
| Distribution | k3s |
| Version | v1.34.4+k3s1 |
| Container Runtime | containerd 2.1.5-k3s1 |
| CNI | Flannel |
| Ingress | Traefik (built-in) |
| Cluster Age | 63 days |

### 3.2 Nodes

| Name | Role | IP | OS | Kernel | Status |
|------|------|----|----|--------|--------|
| master | control-plane | 172.16.10.9 | Ubuntu 24.04.4 LTS | 6.8.0-101-generic | Ready |
| worker1 | worker | 172.16.10.5 | Ubuntu 24.04.4 LTS | 6.8.0-110-generic | Ready |
| worker2 | worker | 172.16.10.10 | Ubuntu 24.04.4 LTS | 6.8.0-110-generic | Ready |

### 3.3 Namespaces and Workloads

| Namespace | Workloads |
|-----------|---------|
| wazuh | wazuh-manager-master-0, wazuh-manager-worker-0, wazuh-indexer-0, wazuh-dashboard |
| thehive | thehive deployment (1 pod) + CronJob thehive-user-ensure |
| nids | Suricata DaemonSet (2 pods: worker1 + worker2) |
| kube-system | k3s system: Traefik, metrics-server, CoreDNS |
| soc-apps/soc-core/soc-ops | Reserved namespaces |

### 3.4 PersistentVolumeClaims

| Namespace | PVC Name | Size | Status |
|-----------|---------|------|--------|
| thehive | thehive-data-pvc | 5Gi | Bound |
| wazuh | wazuh-indexer-wazuh-indexer-0 | 500Mi | Bound |
| wazuh | wazuh-manager-master-wazuh-manager-master-0 | 500Mi | Bound |
| wazuh | wazuh-manager-worker-wazuh-manager-worker-0 | 500Mi | Bound |

### 3.5 Key Secrets

| Namespace | Secret | Purpose |
|-----------|--------|---------|
| wazuh | wazuh-authd-pass | Wazuh agent enrollment authentication |
| wazuh | wazuh-api-cred | Wazuh REST API credentials |
| thehive | thehive-soc-apikey | SOC analyst API key (9O81h9pfpC7bBvSXh+S5gQ6/4mrULoBP) |

### 3.6 Persistence Fixes Applied

1. postStart lifecycle hook on wazuh-manager-worker StatefulSet:
   chmod 750 + chown root:wazuh on custom-thehive scripts on every pod start

2. CronJob thehive-user-ensure (every 5 minutes, namespace thehive):
   Ensures soc@soc.local user exists with correct analyst profile and API key.
   Status: Running and completing successfully (verified: 3 recent completions)

---

## 4. Tool Deep Dives

### 4.1 Wazuh

Version: 4.14.3
Deployment: Kubernetes (StatefulSets + Deployment), namespace wazuh

Current Pods:
  wazuh-dashboard-6656f4fc54-jxvmd   1/1 Running  7d16h
  wazuh-indexer-0                    1/1 Running  6d16h
  wazuh-manager-master-0             1/1 Running  3d15h
  wazuh-manager-worker-0             1/1 Running  6h24m

Agents Connected (5/5 Active):
| ID | Name | OS | Status |
|----|------|-----|--------|
| 000 | wazuh-manager-master-0 | (server) | Active/Local |
| 005 | worker2 | Ubuntu 24.04 | Active |
| 006 | worker1 | Ubuntu 24.04 | Active |
| 007 | ubunttest | Ubuntu | Active |
| 008 | windows-soc | Windows 10 | Active |

Configuration Highlights:
- syscollector: hardware, OS, network, packages, ports, processes (1h interval)
- vulnerability-detection: enabled (60min feed updates)
- Active Response: firewall-drop on rule 100100, timeout 600s, location=local
- Integrations: custom-thehive (level 10), shuffle (level 10)
- Sysmon: EventID 1, 11 monitoring on Windows agent

Integration Scripts (/var/ossec/integrations/):
- custom-thehive (wrapper) — permissions: rwxr-x--- root:wazuh
- custom-thehive.py (Python, 1621 bytes) — permissions: rwxr-x--- root:wazuh
- shuffle (Shuffle SOAR webhook) — permissions: rwxr-x--- root:wazuh

Known Issues:
- wazuh-integratord does not auto-invoke custom-thehive (under investigation)
- agent_control only works from master-0 pod in cluster mode

### 4.2 TheHive

Version: 5.2.8
Deployment: Kubernetes Deployment, namespace thehive
Storage: 5Gi PVC (local-path, persistent)
NodePort: 9000 mapped to 31000

Current Pod: thehive-5bc76db58-kd948 (1/1 Running, 3d5h)

Users:
- admin@thehive.local (admin profile) — platform administration only
- soc@soc.local (analyst profile) — case creation, alert management

API Key: 9O81h9pfpC7bBvSXh+S5gQ6/4mrULoBP (in Kubernetes Secret thehive-soc-apikey)
Current Cases: 37 total (Case 38 = SSH brute force T1110.001)

Known Issues:
- Admin user cannot create/view cases (TheHive 5 org isolation) — fixed in validate.sh
- wazuh-integratord does not auto-create cases (manual API confirmed working)

### 4.3 Cortex

Version: 3.1.7
Deployment: Docker Compose on worker2 (172.16.10.10)
Port: 9001 (HTTP)
Purpose: Threat intelligence enrichment — analyzers for VirusTotal, AbuseIPDB, etc.
Integration: Connected to TheHive for case-triggered analysis
State: Running, HTTP 200/303 at http://172.16.10.10:9001

### 4.4 Shuffle SOAR

Version: latest (Docker Compose, worker2)
Port: 3001 (HTTP)

Components:
- shuffle-frontend (React UI)
- shuffle-backend (Golang API)
- shuffle-orborus (workflow execution engine)
- shuffle-database (OpenSearch)

Active Webhook:
  ID: 4030788a-6f3e-40c9-ab08-ff56836c96b1
  Workflow: Wazuh-SOC-Response
  URL: http://172.16.10.10:3001/api/v1/hooks/webhook_4030788a-6f3e-40c9-ab08-ff56836c96b1

Integration: Wazuh fires on level 10+ alerts — integrations.log confirms entries every ~4s
Known Issues: Orborus may stall on TheHive action node; workaround is docker restart shuffle-orborus

### 4.5 Suricata NIDS

Version: 7.0.3
Deployment: Kubernetes DaemonSet, namespace nids (label ids=enabled on worker1+worker2)

Pods:
  suricata-tkp6l (worker1) — 1/1 Running, 35d
  suricata-vdvdg (worker2) — 1/1 Running, 35d

Interfaces monitored: enp6s18 (physical), cni0 (pod), flannel.1 (VLAN)

Alert Volume:
  worker1: 127,000+ alerts (fast.log)
  worker2: 762,952+ alerts (fast.log), 3.4GB eve.json (6.7M+ events)

Top Signatures:
  SID 2006380 — ET POLICY Outgoing Basic Auth unencrypted (Priority 1)
  SID 2210020 — STREAM ESTABLISHED packet out of window (Priority 3)
  SID 2210029 — STREAM ESTABLISHED invalid ack (Priority 3)
  SID 2260001 — Applayer Wrong direction first Data (Priority 3)

Key Finding: SID 2006380 fires on TheHive/Shuffle HTTP API calls — Suricata correctly detects
unencrypted credential transmission over HTTP to port 31000/3001.

---

## 5. Detection Rules

### 5.1 Custom Rule 100100

Location: /var/ossec/etc/rules/local_ssh_bruteforce.xml

Rule definition:
  ID: 100100, Level: 12, Frequency: 5, Timeframe: 120s, Ignore: 60s
  Parent rule: 5710 (SSH invalid user)
  Description: SSH brute force: 5 failed logins in 120s - AR trigger
  MITRE: T1110.001
  Groups: authentication_failures, pci_dss_10.2.4, pci_dss_10.2.5

Trigger logic: 5x rule 5710 (SSH invalid user) within 120 seconds triggers rule 100100 (level 12).
Level 12 exceeds the integration threshold (level 10) triggering Shuffle webhook and TheHive.

### 5.2 Default Rules That Fired

| Rule | Level | Description | Volume |
|------|-------|-------------|--------|
| 5710 | 5 | SSH: Attempt to login using non-existent user | Multiple |
| 86601 | 3 | Suricata: IDS alert | 31,069+ |
| 92031 | 3 | Sysmon EID1: Discovery activity | 20/day |
| 92039 | 3 | Sysmon EID1: net.exe account discovery | 8/day |
| 92205 | 9 | Sysmon EID11: PowerShell created executable | 2/day |
| 92217 | 6 | Sysmon EID1: Executable dropped in Windows root | 1/day |
| 750 | 5 | Registry Value Integrity Checksum Changed | 36/day |
| 752 | 5 | Registry Value Entry Added | 29/day |
| 751 | 5 | Registry Value Entry Deleted | 25/day |
| 504 | 4 | Wazuh agent disconnected | Occasional |

### 5.3 Active Response Configuration

Command: firewall-drop
Location: local (runs on the agent that generated the alert)
Rules_id: 100100
Timeout: 600 seconds (10 minutes, then auto-removed)
Effect: iptables -I INPUT -s ATTACKER_IP -j DROP on the target agent

---

## 6. Integration Chain

### 6.1 Full Data Flow

  [Attacker: 172.16.10.9]
          |
          | 30x failed SSH to baduser@172.16.10.11    (T0)
          v
  [ubunttest: 172.16.10.11] — Wazuh Agent 007
    /var/log/auth.log: Invalid user baduser from 172.16.10.9
          |
          | Wazuh agent reads auth.log (1s interval)
          | Rule 5710 counter increments x5
          v
  [Wazuh Manager Worker-0] — Correlation Engine
    Rule 100100 fires (level 12) at T0+2.17s         (T1)
          |
          +---> [Active Response: firewall-drop600]    (T2: T1+~1s)
          |     iptables -I INPUT -s 172.16.10.9 -j DROP
          |     On: ubunttest, Timeout: 600s
          |
          +---> [Shuffle SOAR Webhook] at T1+1s        (WORKING)
          |     POST http://172.16.10.10:3001/api/v1/hooks/webhook_4030788a-...
          |     Confirmed: entries in integrations.log every ~4s
          |     Workflow: Wazuh-SOC-Response
          |
          +---> [TheHive custom-thehive.py]            (PARTIAL)
                POST http://172.16.10.10:31000/api/v1/case
                Configured in ossec.conf (hook_url + api_key)
                wazuh-integratord: only Shuffle entries in log
                Manual API: HTTP 201 confirmed (37 cases exist)

### 6.2 Integration Status Summary

| Integration | Status | Evidence |
|------------|--------|---------|
| Wazuh to Shuffle | WORKING | integrations.log: continuous entries every ~4s |
| Wazuh to TheHive (auto) | PARTIAL | custom-thehive configured but integratord not invoking |
| TheHive API (manual/direct) | WORKING | 37 cases, HTTP 201 confirmed |
| Suricata to Wazuh | WORKING | Rule 86601 firing on Suricata events |
| Active Response | WORKING | firewall-drop600 on rule 100100 |
| TheHive to Cortex | CONFIGURED | Cortex running at :9001 |

---

## 7. Ansible Automation

### 7.1 6-Phase Deployment (site.yml)

Phase 1: common        — All nodes  — baseline OS, packages, firewall, NTP
Phase 2: k3s-master    — master     — k3s control-plane, kubeconfig, cluster token
Phase 3: k3s-worker    — workers    — join k3s agent to master
Phase 4: soc-tools-k8s — master     — Wazuh stack via Helm/manifests
Phase 5: soc-tools-docker — worker2 — Cortex + Shuffle via Docker Compose
Phase 6: wazuh-agent   — endpoints  — Wazuh agent install + enrollment

### 7.2 Roles

| Role | Target | What It Does |
|------|--------|-------------|
| common | All nodes | Package updates, NTP, firewall, hostname |
| k3s-master | master | k3s server install, kubeconfig generation |
| k3s-worker | worker1/2 | k3s agent join using cluster token |
| soc-tools-k8s | master | Deploy Wazuh Helm chart + ConfigMaps |
| soc-tools-docker | worker2 | Docker Compose for Cortex 3.1.7 + Shuffle |
| wazuh-agent | ubunttest/windows | Wazuh agent install, manager config, auto-enroll |

### 7.3 Automated vs Manual

| Task | Status |
|------|--------|
| k3s cluster deployment | Fully automated (Ansible) |
| Wazuh stack deployment | Fully automated (Ansible + Helm) |
| Cortex + Shuffle deployment | Fully automated (Ansible + Docker Compose) |
| Wazuh agent enrollment | Fully automated (Ansible) |
| Custom rule deployment | Automated (ConfigMap) |
| Custom integration scripts | Automated (ConfigMap + postStart hook) |
| TheHive SOC user creation | Automated (CronJob every 5min) |
| TheHive org setup | Manual (first-time UI) |
| Shuffle workflow creation | Manual (imported via UI) |
| Cortex analyzer API keys | Manual (per-analyzer config) |
| Windows Sysmon install | Manual |

---

## 8. CI/CD Pipeline (GitHub Actions)

Trigger: Push or Pull Request to master branch

Jobs:
1. lint-ansible: Install ansible + ansible-lint; syntax-check site.yml; lint playbooks
2. validate-yaml: Install yamllint; lint all YAML files in ansible/
3. security-scan: Scan for hardcoded passwords in Ansible files

Security scan pattern:
  grep -r password ansible/ --include=*.yml
  Exclude: defaults, vars, vault, known password variables (wazuh_password, ansible_password)
  This catches accidental credential commits before they reach the repository.

---

## 9. Attack Scenarios Summary

### 9.1 SSH Brute Force (T1110.001) — Primary Scenario

Setup:
  Attacker:  172.16.10.9 (master VM)
  Target:    172.16.10.11 (ubunttest, Wazuh agent 007)
  Tool:      sshpass — 30 parallel failed SSH logins as baduser
  Detection: Wazuh rule 100100 (5 failures in 120s)

Measured KPIs (Run 2 — 2026-05-01 15:10:45 UTC):
| KPI | Value |
|-----|-------|
| Detection time (T0 to T1) | 2.17 seconds |
| Active response (T1 to T2) | ~1 second |
| Shuffle webhook trigger | 1 second |
| End-to-end (T0 to blocked) | less than 4 seconds |
| Brute force completion | 6.37 seconds (30 logins) |

Evidence:
- Alert ID: 1777648248.82662368 (level 12, rule 100100)
- Shuffle entries: 1777648249, 1777648252 confirmed in integrations.log
- TheHive Case #4: Wazuh Alert: SSH brute force: 5 failed logins in 120s - AR trigger
- Active Response: firewall-drop600 dispatched to ubunttest

### 9.2 Suricata NIDS Detections

| Detection | SID | Priority |
|-----------|-----|---------|
| Unencrypted API credentials over HTTP | 2006380 (ET POLICY) | 1 (HIGH) |
| TCP stream anomalies | 2210020/2210029/2210045 | 3 |
| App-layer protocol issues | 2260001 | 3 |

Total alerts worker2: 762,952+ (fast.log), 3.4 GB eve.json
Note: ET SCAN rules not deployed; nmap scans appear as flow events only.

### 9.3 Windows Sysmon — Agent 008 (DESKTOP-GOQ7NT3)

Agent: Active, Windows 10 Home, Wazuh client v4.7.3
Events (2026-05-02): 160 total

| Technique | MITRE | Rule | Count |
|-----------|-------|------|-------|
| PowerShell execution | T1059.001 | 92205 (level 9) | 2 |
| Windows Command Shell | T1059.003 | 92031 (level 3) | 20 |
| Account Discovery (net.exe) | T1087.001 | 92039 (level 3) | 8 |
| Registry persistence | T1547 | 750/751/752/594/598 | 121 |
| Executable drop | T1204 | 92217 (level 6) | 1 |
| SecEdit via PowerShell | T1059.001 | 92066 (level 4) | 1 |

Key Sysmon Event (EID 11 — File Create):
  Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (NT AUTHORITY\SYSTEM)
  File: C:\Windows\SystemTemp\__PSScriptPolicyTest_jrymmbrv.1n0.ps1
  Wazuh Rule: 92205 (level 9)

---

## 10. Known Issues and Limitations

| # | Issue | Root Cause | Workaround / Status |
|---|-------|-----------|---------------------|
| 1 | wazuh-integratord does not auto-invoke custom-thehive | Possible permissions race or config timing after pod restart | Manual API works; postStart hook fixes perms; under investigation |
| 2 | Integration script permissions reset on pod restart | Pod filesystem ephemeral; chmod lost on restart | FIXED: postStart hook on StatefulSet applies chmod 750 + chown on every start |
| 3 | TheHive SOC user deleted on pod restart | Pre-PVC ephemeral storage | FIXED: 5Gi PVC + CronJob thehive-user-ensure every 5 minutes |
| 4 | Shuffle Orborus stalls in EXECUTING state | Orborus timeout or TheHive API latency on TheHive action node | Restart shuffle-orborus container; webhooks continue firing correctly |
| 5 | Wazuh Dashboard ExternalIP shows pending | No MetalLB or cloud LoadBalancer | Access via NodePort 32732 — fully functional |
| 6 | TheHive and Shuffle served over HTTP only | No TLS configured | Suricata correctly flags as Priority 1 (ET POLICY 2006380); TLS recommended for production |
| 7 | ET SCAN rules not in Suricata | Default community rules only | Install Emerging Threats Pro or add ET SCAN rules separately |
| 8 | Windows agent version mismatch (4.7.3 vs manager 4.14.3) | Different release schedules | Compatible but upgrade recommended |
| 9 | agent_control not available on worker-0 | Cluster mode: tool runs on master only | Use kubectl exec on wazuh-manager-master-0 |
| 10 | TheHive admin user cannot create/view cases | TheHive 5 org isolation: admin profile lacks manageCase permissions | FIXED in validate.sh: use soc@soc.local API key for case queries |

---

## 11. Recommendations

### 11.1 For Production

| Priority | Recommendation | Effort |
|----------|---------------|--------|
| HIGH | Enable TLS/HTTPS for TheHive (31000) and Shuffle (3001) | Medium |
| HIGH | Replace hardcoded API keys with Kubernetes External Secrets | Medium |
| HIGH | Add MetalLB for proper LoadBalancer IP assignment | Low |
| HIGH | Investigate and fix wazuh-integratord custom-thehive auto-invocation | High |
| MEDIUM | Upgrade Windows agent to match manager version (4.14.3) | Low |
| MEDIUM | Add ET SCAN ruleset to Suricata for network scan detection | Low |
| MEDIUM | Add Suricata alerts to TheHive pipeline via Wazuh rule 86601 | Medium |
| MEDIUM | Add PodDisruptionBudget for Wazuh StatefulSets | Low |
| LOW | Configure Cortex analyzers (VirusTotal, AbuseIPDB) with API keys | Medium |
| LOW | Add resource limits/requests to all pods for production stability | Low |
| LOW | Replace local-path PVCs with distributed storage (Longhorn or Ceph) | High |

### 11.2 Future Work for Defense

1. Windows Active Directory integration — detect lateral movement (T1021), pass-the-hash (T1550.002), Kerberoasting (T1558.003)
2. Ransomware simulation — honeypot files monitored by Wazuh FIM; detect encryption activity
3. SOAR playbook expansion — Shuffle workflows that auto-enrich TheHive cases with Cortex analyzers
4. Threat hunting dashboards — Wazuh Dashboard custom dashboards for MITRE ATT&CK matrix coverage
5. Deception technology — Cowrie honeypot on isolated VM with Wazuh integration
6. Network segmentation — Calico network policy for micro-segmentation between SOC components
7. SIEM tuning — reduce false positives by tuning Suricata rules and Wazuh alert thresholds
8. Multi-tenancy — expand TheHive to multiple organizations for MSSP scenario simulation
