# Report Update Summary
## ESPRIT PFE 2025-2026 — Ismail Triki

### Compilation Status
- Engine: pdflatex (TeX Live 2023)
- Pages: 61
- Errors: 0
- Warnings: 0 (bibtex: 0 after fixing @report → @techreport, @standard → @misc)

### Word Count
- Before: 1,770 lines (original English draft)
- After:  1,893 lines + references.bib (23 entries)

### Sections Added or Modified

| Section | Status | Notes |
|---------|--------|-------|
| Abstract | Modified | Updated 14/14 → 17/17; added AWX/Terraform; 847+ cases |
| List of Abbreviations | Modified | Added AWX, IaC, KVM |
| General Introduction | Modified | Added DevSecOps pipeline objective |
| Chapter 1 | Modified | Merged context + state of art; expanded comparison table |
| Chapter 2 | Modified | Added DevSecOps pipeline diagram (TikZ); AWX local demo table; deployment TikZ diagram |
| Chapter 3 | Modified | Fixed Ansible role names (common/soc-tools-k8s/soc-tools-docker/wazuh-agent); added rules 100101/100102/100103; added AWX section; added Terraform IaC section |
| Chapter 4 | Modified | Added Scenario 2 (T1548.003 privilege escalation); fixed 14/14 → 17/17; 17-check table; 847+ cases in KPI box |
| Conclusion | Modified | Updated all KPIs; added AWX/Terraform to achievements |
| Appendix A | Modified | Updated validate.sh to real 17-check version |
| Appendix B | Added | MITRE ATT&CK technique details table |
| Appendix C | Added | Platform architecture diagram reference |

### LaTeX Packages Added
- `tcolorbox` (with skins, breakable library) — KPI/info/alert boxes
- `acronym` — abbreviations management
- `minitoc` — per-chapter mini table of contents
- `amssymb` — \checkmark symbol
- `pifont` — additional symbols
- `tikz` libraries: arrows.meta, positioning, fit, backgrounds, calc, shadows

### Fixes Applied
1. 14/14 → **17/17** validation checks throughout
2. Ansible role names corrected: `base` → `common`, `wazuh` → `soc-tools-k8s`, `nids` → (merged), `soc-tools` → `soc-tools-docker` + `wazuh-agent`
3. Wazuh API port: 32000 → **30947**
4. TheHive cases: 4 → **847+** (per measured KPI)
5. Footer: added **Ismail Triki** on left; added ESPRIT on right
6. `language=yaml` / `language=xml` removed from lstlisting (not defined in listings package)
7. Created `report/figures/` directory (TikZ diagrams used instead of external images)
8. Fixed `\end{lstlisting>` typo (was in original draft)
9. Added `\nocite{*}` to include all bibliography entries

### Bibliography
- File created: `report/references.bib` (23 entries)
- Coverage: Wazuh, TheHive, Cortex, Suricata, Shuffle, k3s, Kubernetes, Ansible, Terraform libvirt, AWX, MITRE ATT&CK, Docker, Sysmon, Proxmox, IBM Breach 2024, ISO 27001, PCI-DSS, NIST CSF, Emerging Threats, CIS Windows, 2 academic papers (Vaarandi 2014, Mohasseb 2023)

### Infrastructure Issues Found
See `docs/issues-found.md` for 7 non-blocking issues logged.
