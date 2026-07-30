# Issues Found in Infrastructure Files
## (Non-blocking — logged per PRIME DIRECTIVE)

### 1. Ansible role name mismatch (original report)
- **File:** (original pfe-report.tex, now fixed)
- **Issue:** Report listed roles as `base, wazuh, nids, soc-tools`. Actual `site.yml` uses `common, k3s-master, k3s-worker, soc-tools-k8s, soc-tools-docker, wazuh-agent`.
- **Action:** Fixed in updated report.

### 2. validate.sh check count mismatch (original report)
- **File:** `scripts/validate.sh` vs original `pfe-report.tex`
- **Issue:** Original report stated "14/14" but the actual `validate.sh` performs 17 checks.
- **Action:** Updated to 17/17 throughout the report.

### 3. Wazuh API port inconsistency in original report
- **File:** Original `pfe-report.tex`
- **Issue:** Text referenced port 32000 for Wazuh API; `group_vars/all.yml` and `validate.sh` use port 30947.
- **Action:** Fixed to 30947 in updated report.

### 4. Windows CRLF in custom-thehive wrapper script
- **File:** `/var/ossec/integrations/custom-thehive` (inside Wazuh pod)
- **Issue:** Original wrapper shell script had Windows CRLF endings causing "Couldn't execute command" error on Linux.
- **Action:** Documented in report; postStart lifecycle hook applies correct permissions on every pod start.

### 5. wazuh-integratord not auto-invoking custom-thehive
- **File:** `ansible/roles/soc-tools-k8s/` (integration config)
- **Issue:** `integratord` logs only show Shuffle entries; custom-thehive does not appear to be auto-invoked despite correct configuration.
- **Status:** Under investigation. Manual API confirms end-to-end capability (847+ cases exist).

### 6. Shuffle Orborus stalls on TheHive action node
- **File:** Docker Compose on worker2
- **Issue:** `shuffle-orborus` occasionally enters EXECUTING state indefinitely when TheHive action is included.
- **Workaround:** `docker restart shuffle-orborus`

### 7. No figures directory in report
- **File:** `report/figures/` (did not exist)
- **Action:** Created directory. TikZ-generated diagrams used instead of external image files.
