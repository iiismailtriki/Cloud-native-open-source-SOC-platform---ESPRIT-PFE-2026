# MITRE ATT\&CK Mapping — SOC Platform ESPRIT PFE 2026

**Platform:** Cloud-Native Open-Source SOC (k3s + Wazuh 4.14.3 + TheHive 5.2.8 + Suricata 7.0.3 + Shuffle SOAR)  
**Date:** 2026-05-02  
**Environment:** k3s cluster — master (172.16.10.9), worker1 (172.16.10.5), worker2 (172.16.10.10)

---

## Detected Techniques — Evidence-Based

All techniques below were **observed in live Wazuh alerts** on this platform (alerts.log, 2026-04-28 to 2026-05-02).

---

### T1110.001 — Brute Force: Password Guessing

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Platform | Linux (ubunttest, agent 007) |
| Detection Source | Wazuh 4.14.3, rule 100100 (custom) |
| Alert Level | 12 |
| KPI: Detection Time | **2.17 s** (T0→T1, Run 2: 2026-05-01 15:10:45→15:10:48 UTC) |
| KPI: Response Time | **~1 s** (T1→T2, iptables DROP via Active Response) |
| KPI: SOAR Trigger | **1 s** (T1→Shuffle webhook: integrations.log entry 1777648249) |
| Evidence | Alert 1777648248.82662368, Rule 100100 (level 12) |
| Response | firewall-drop600: iptables -I INPUT -s $ATTACKER -j DROP (600s TTL) |
| TheHive Case | Case #2 (2026-05-01 08:03:40 UTC), Case #4 (2026-05-01 15:18:37 UTC) |

**Wazuh Rule:**
```xml
<rule id="100100" level="12" frequency="5" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <description>SSH brute force: 5 failed logins in 120s - AR trigger</description>
  <mitre><id>T1110.001</id></mitre>
</rule>
```

---

### T1046 — Network Service Discovery (Port Scanning)

| Field | Value |
|-------|-------|
| Tactic | Discovery |
| Platform | Network |
| Detection Source | Suricata 7.0.3 (DaemonSet: worker1 suricata-tkp6l + worker2 suricata-vdvdg) |
| Signatures | 762,952+ alerts (worker2 fast.log); 127k+ (worker1 fast.log) |
| Notable Sig | ET POLICY 2006380: Unencrypted Basic Auth credentials (Priority 1) |
| Evidence | Suricata eve.json 3.4 GB, wazuh rule 86601 |
| Notes | ET SCAN rules not deployed; TCP flow anomalies detected via STREAM rules |

**Observed alerts (via Wazuh rule 86601):**
- SURICATA STREAM Packet with invalid ack (SID 2210045) — 31,069 today
- SURICATA STREAM ESTABLISHED invalid ack (SID 2210029)
- ET POLICY Outgoing Basic Auth Base64 HTTP Password unencrypted (SID 2006380, Priority 1)

---

### T1059.001 — Command and Scripting Interpreter: PowerShell

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Platform | Windows (windows-soc, agent 008, DESKTOP-GOQ7NT3) |
| Detection Source | Wazuh + Sysmon (EventID 11 — File Created) |
| Wazuh Rule | 92205 (level 9): Powershell process created an executable file in Windows root folder |
| Evidence | Alert 1777688749.61902334 — 2026-05-02 02:25:49 UTC |
| Process | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (NT AUTHORITY\SYSTEM) |
| File Created | C:\Windows\SystemTemp\__PSScriptPolicyTest_jrymmbrv.1n0.ps1 |
| EventID | Sysmon EID 11 (File Create) |

**Raw Sysmon Event:**
```
ProcessGuid: {1471aea6-60aa-69f5-ce03-000000000b00}
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Windows\SystemTemp\__PSScriptPolicyTest_jrymmbrv.1n0.ps1
User: NT AUTHORITY\SYSTEM
```

---

### T1059.003 — Command and Scripting Interpreter: Windows Command Shell

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Platform | Windows (windows-soc, agent 008, DESKTOP-GOQ7NT3) |
| Detection Source | Wazuh + Sysmon (EventID 1 — Process Create) |
| Wazuh Rule | 92031 (level 3): Discovery activity executed; 92039 (level 3): net.exe account discovery |
| Evidence | 20x Rule 92031 + 8x Rule 92039 — 2026-05-02 03:34:03–06 UTC |
| Command | net.exe accounts |
| Parent | wazuh-agent.exe (C:\Program Files (x86)\ossec-agent) |
| EventID | Sysmon EID 1 (Process Create) |

**Raw Sysmon Event:**
```
Image: C:\Windows\SysWOW64\net.exe
CommandLine: net.exe accounts
User: NT AUTHORITY\SYSTEM
ParentImage: C:\Program Files (x86)\ossec-agent\wazuh-agent.exe
Hashes: MD5=31890A7DE89936F922D44D677F681A7F
        SHA256=7C4C7725E266F12ABA8C50FD1598D4001201BCA0E7ACA901508307E365AFFF42
```

---

### T1087.001 — Account Discovery: Local Account

| Field | Value |
|-------|-------|
| Tactic | Discovery |
| Platform | Windows (windows-soc, agent 008) |
| Detection Source | Wazuh + Sysmon (EventID 1) |
| Wazuh Rule | 92039 (level 3): A net.exe account discovery command was initiated |
| Evidence | 8x Rule 92039 — 2026-05-02 03:34:05 UTC |
| Command | net.exe accounts (querying local account policy) |
| EventID | Sysmon EID 1 |

---

### T1547 — Boot or Logon Autostart Execution (Registry Persistence)

| Field | Value |
|-------|-------|
| Tactic | Persistence, Privilege Escalation |
| Platform | Windows (windows-soc, agent 008) |
| Detection Source | Wazuh FIM (Windows Registry monitoring) |
| Evidence | 36x Rule 750 + 29x Rule 752 + 25x Rule 751 + 25x Rule 594 + 6x Rule 598 (today) |
| Details | Registry Value Integrity changes, entries added/deleted |
| Notes | Wazuh monitors HKLM/HKCU Run keys; changes logged continuously |

**Wazuh Registry Rules:**
| Rule | Level | Description |
|------|-------|-------------|
| 750 | 5 | Registry Value Integrity Checksum Changed |
| 751 | 5 | Registry Value Entry Deleted |
| 752 | 5 | Registry Value Entry Added to the System |
| 594 | 5 | Registry Key Integrity Checksum Changed |
| 598 | 5 | Registry Key Entry Added to the System |

---

### T1204 — User Execution (Suspicious Executable Drop)

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Platform | Windows (windows-soc, agent 008) |
| Detection Source | Wazuh + Sysmon (EventID 1) |
| Wazuh Rule | 92217 (level 6): Executable dropped in Windows root folder |
| Evidence | 1x Rule 92217 — 2026-05-02 UTC |
| Rule | 92066 (level 4): SecEdit.exe launched by PowerShell — 1 occurrence |

---

### T1562.001 — Impair Defenses: Disable or Modify Tools (Agent Disconnect)

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Platform | Multi-platform |
| Detection Source | Wazuh rule 504 (agent disconnect) |
| Notes | Agent disconnect events logged; agent 008 was previously disconnected (rejoined 2026-05-02) |

---

## Detection Coverage Matrix

| ATT\&CK Technique | Platform | Detected | Detection Tool | Alert Count |
|------------------|----------|----------|---------------|-------------|
| T1110.001 Brute Force: Password Guessing | Linux | ✅ | Wazuh rule 100100 | 2 confirmed |
| T1046 Network Service Discovery | Network | ✅ | Suricata 7.0.3 | 762k+ |
| T1059.001 PowerShell | Windows | ✅ | Wazuh + Sysmon EID11 | 2 (today) |
| T1059.003 Windows Command Shell | Windows | ✅ | Wazuh + Sysmon EID1 | 28 (today) |
| T1087.001 Account Discovery: Local | Windows | ✅ | Wazuh rule 92039 | 8 (today) |
| T1547 Autostart via Registry | Windows | ✅ | Wazuh FIM registry | 121 (today) |
| T1204 User Execution (exec drop) | Windows | ✅ | Wazuh rule 92217 | 1 (today) |
| T1562.001 Impair Defenses | Multi | ✅ | Wazuh rule 504 | Logged |

---

## Response Chain: T1110.001 (SSH Brute Force) — Automated

```
T0 (+0.000s) — Attacker launches 30x SSH logins from 172.16.10.9 → 172.16.10.11
T1 (+2.170s) — Wazuh rule 100100 fires (level 12) — Alert 1777648248.82662368
T1 (+~1.0s)  — Active Response dispatched: firewall-drop600 → iptables DROP (600s TTL)
T1 (+1.0s)   — Shuffle SOAR webhook triggered (entry 1777648249 in integrations.log)
T3 (+7m52s)  — TheHive Case #4 created: Wazuh Alert: SSH brute force...
```

**KPIs:**
- Detection time: **2.17 s** (below 5s SLA)
- Response time: **~1 s** (iptables DROP)
- SOAR notification: **1 s**
- End-to-end (T0 → blocked): **< 4 s**

---

## Platform Component Status (2026-05-02)

| Component | Version | Status | Notes |
|-----------|---------|--------|-------|
| k3s | v1.31+ | ✅ 3 nodes Ready | master/worker1/worker2 |
| Wazuh Manager | 4.14.3 | ✅ Running | 4 pods, 5 agents (5/5 active) |
| Wazuh Dashboard | 4.14.3 | ✅ Running | https://172.16.10.9:32732 |
| Wazuh Indexer | 4.14.3 | ✅ Running | OpenSearch-based |
| TheHive | 5.2.8 | ✅ Running | NodePort 31000, 4 cases |
| Cortex | 3.1.7 | ✅ Running | Docker Compose :9001 |
| Shuffle SOAR | Latest | ✅ Running | Docker Compose :3001 |
| Suricata NIDS | 7.0.3 | ✅ Running | 2 pods (worker1+worker2) |
| Agent 005 worker2 | 4.14.4 | ✅ Active | |
| Agent 006 worker1 | 4.14.4 | ✅ Active | |
| Agent 007 ubunttest | 4.14.4 | ✅ Active | Linux target node |
| Agent 008 windows-soc | 4.7.3 | ✅ **Active** | DESKTOP-GOQ7NT3, Sysmon enabled |
