#!/bin/bash
export KUBECONFIG=/home/socadmin/.kube/config
echo "=========================================="
echo "   SOC Platform - Full Validation"
echo "   $(date)"
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
check "Wazuh pods running ($PODS/4)" $([ "$PODS" -ge 4 ] && echo OK || echo FAIL) "expected 4+"

THEHIVE_POD=$(kubectl get pods -n thehive --no-headers 2>/dev/null | grep -c Running)
check "TheHive pod running" $([ "$THEHIVE_POD" -ge 1 ] && echo OK || echo FAIL) "expected 1+"

SURI=$(kubectl get pods -n nids --no-headers 2>/dev/null | grep -c Running)
check "Suricata NIDS pods ($SURI)" $([ "$SURI" -ge 1 ] && echo OK || echo FAIL) "expected 1+"

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
check "Wazuh API authentication" $([ -n "$TOKEN" ] && echo OK || echo FAIL) "no token"

# TheHive: verify API reachable and count cases via SOC analyst API key
SOC_API_KEY="9O81h9pfpC7bBvSXh+S5gQ6/4mrULoBP"
THEHIVE_RESP=$(curl -s -H "Authorization: Bearer ${SOC_API_KEY}" \
  -X POST "http://172.16.10.10:31000/api/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"query": [{"_name": "listCase"}]}' 2>/dev/null)
CASES=$(echo "$THEHIVE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null)
check "TheHive API accessible" $([ -n "$CASES" ] && echo OK || echo FAIL) "no response"
check "TheHive has cases ($CASES >= 1)" $([ -n "$CASES" ] && [ "$CASES" -ge 1 ] && echo OK || echo FAIL) "no cases found — run SSH brute force test to generate alerts"

# TheHive: verify soc@soc.local user exists
SOC_USER_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://172.16.10.10:31000/api/v1/user/soc@soc.local" \
  -u "admin@thehive.local:secret")
check "TheHive soc@soc.local user" $([ "$SOC_USER_STATUS" = "200" ] && echo OK || echo FAIL) "HTTP $SOC_USER_STATUS"

S=$(curl -s -X POST \
  "http://172.16.10.10:3001/api/v1/hooks/webhook_4030788a-6f3e-40c9-ab08-ff56836c96b1" \
  -H "Content-Type: application/json" \
  -d '{"test": "validation"}' | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if d.get('success') else 'FAIL')" 2>/dev/null)
check "Shuffle webhook" "$S" "no response"

AR=$(kubectl exec -n wazuh wazuh-manager-master-0 -- \
  /var/ossec/bin/agent_control -L 2>/dev/null | grep -c "firewall-drop")
check "Active Response configured" $([ "$AR" -ge 1 ] && echo OK || echo FAIL) "AR not found"

SURI=$(kubectl get pods -n nids --no-headers 2>/dev/null | grep -c Running)
check "Suricata NIDS ($SURI pods)" $([ "$SURI" -ge 1 ] && echo OK || echo FAIL) "no running pods"

# Wazuh integration scripts present
INTEG=$(kubectl exec -n wazuh wazuh-manager-worker-0 -- ls /var/ossec/integrations/custom-thehive 2>/dev/null | wc -l)
check "custom-thehive integration script" $([ "$INTEG" -ge 1 ] && echo OK || echo FAIL) "script missing"

echo ""
echo "=========================================="
TOTAL=$((PASS+FAIL))
echo "  PASSED: $PASS / $TOTAL"
echo "  FAILED: $FAIL / $TOTAL"
[ "$FAIL" -eq 0 ] && echo "  STATUS: ALL SYSTEMS OPERATIONAL" || echo "  STATUS: $FAIL CHECK(S) FAILED"
echo "=========================================="
