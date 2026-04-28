# Compliance Mapping — ISO 27001

| Wazuh Rule | Description | ISO 27001 Control | PCI-DSS |
|---|---|---|---|
| 100100 | SSH brute force: 5 failures/120s | A.9.4.2 Secure log-on | 8.3.4 |
| 5710 | Failed SSH authentication | A.9.4.2 Secure log-on | 8.3.4 |
| 60122 | Windows failed logon (Event 4625) | A.9.4.2 Secure log-on | 8.3.4 |
| 92031 | Suspicious process execution (Sysmon) | A.12.4.1 Event logging | 10.2.4 |
| firewall-drop AR | Automatic IP blocking on brute force | A.13.1.1 Network controls | 1.3.2 |

## Active Response as a Security Control

Rule 100100 triggers `firewall-drop600` which inserts an iptables DROP rule
blocking the attacker IP for 600 seconds. This maps to:
- ISO 27001 A.13.1.1: Network controls
- ISO 27001 A.16.1.5: Response to information security incidents
- PCI-DSS 11.4: Intrusion detection/prevention
