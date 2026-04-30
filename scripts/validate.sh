#!/bin/bash
echo "=========================================="
echo "   SOC Platform - Full Validation"
echo "=========================================="

PASS=0
FAIL=0

check() {
  if [ "$2" = "OK" ]; then
    echo "  [OK] $1"
    PASS=$((PASS+1))
  else
    echo "  [FAIL] $1: $3"
    FAIL=$((FAIL+1))
  fi
}

echo ""
echo "--- Infrastructure ---"
NODES=$(kubectl get nodes --no-headers 2>/dev/null | grep -c Ready)
check "k3s nodes ready ($NODES/3)" $([ "$NODES" -eq 3 ] && echo OK || echo FAIL) "expected 3"

PODS=$(kubectl get pods -n wazuh --no-headers 2>/dev/null | grep -c Running)
check "Wazuh pods running ($PODS/4)" $([ "$PODS" -ge 4 ] && echo OK || echo FAIL) "expected 4"

echo ""
echo "--- Agents ---"
AGENTS=$(kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active")
check "Wazuh agents active ($AGENTS)" $([ "$AGENTS" -ge 3 ] && echo OK || echo FAIL) "expected 3+"

echo ""
echo "--- Services ---"
S=$(curl -s -o /dev/null -w "%{http_code}" -k https://172.16.10.9:32732)
check "Wazuh Dashboard" $([ "$S" = "200" ] || [ "$S" = "302" ] && echo OK || echo FAIL) "HTTP $S"

S=$(curl -s -o /dev/null -w "%{http_code}" http://172.16.10.10:31000)
check "TheHive" $([ "$S" = "200" ] || [ "$S" = "302" ] && echo OK || echo FAIL) "HTTP $S"

S=$(curl -s -o /dev/null -w "%{http_code}" http://172.16.10.10:9001)
check "Cortex" $([ "$S" = "200" ] || [ "$S" = "303" ] && echo OK || echo FAIL) "HTTP $S"

S=$(curl -s -o /dev/null -w "%{http_code}" http://172.16.10.10:3001)
check "Shuffle SOAR" $([ "$S" = "200" ] || [ "$S" = "303" ] && echo OK || echo FAIL) "HTTP $S"

echo ""
echo "--- Integration Tests ---"
TOKEN=$(curl -s -k -X POST https://172.16.10.9:30947/security/user/authenticate \
  --user 'wazuh-wui:MyS3cr37P450r.*-' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])" 2>/dev/null)
check "Wazuh API auth" $([ -n "$TOKEN" ] && echo OK || echo FAIL) "no token"

CASES=$(curl -s -u admin@thehive.local:secret \
  -X POST "http://172.16.10.10:31000/api/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"query": [{"_name": "listCase"}]}' | \
  python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
check "TheHive API ($CASES cases)" $([ -n "$CASES" ] && echo OK || echo FAIL) "no response"

S=$(curl -s -X POST \
  "http://172.16.10.10:3001/api/v1/hooks/webhook_4030788a-6f3e-40c9-ab08-ff56836c96b1" \
  -H "Content-Type: application/json" \
  -d '{"test": "validation"}' | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if d.get('success') else 'FAIL')" 2>/dev/null)
check "Shuffle webhook" "$S" "no response"

SURI=$(kubectl get pods -n nids --no-headers 2>/dev/null | grep -c Running)
check "Suricata NIDS ($SURI pods)" $([ "$SURI" -ge 1 ] && echo OK || echo FAIL) "no running pods"

echo ""
echo "=========================================="
echo "  PASSED: $PASS | FAILED: $FAIL"
echo "=========================================="
