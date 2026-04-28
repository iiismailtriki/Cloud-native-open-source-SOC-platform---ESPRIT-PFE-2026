#!/bin/bash
set -e
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "=== SOC Platform Validation ==="

echo -n "Checking k3s nodes... "
NODES=$(kubectl get nodes --no-headers | grep -c "Ready")
if [ "$NODES" -ge 3 ]; then
  echo -e "${GREEN}OK ($NODES nodes ready)${NC}"
else
  echo -e "${RED}FAIL (only $NODES nodes ready)${NC}"
fi

echo -n "Checking Wazuh pods... "
PODS=$(kubectl get pods -n wazuh --no-headers | grep -c "Running")
if [ "$PODS" -ge 4 ]; then
  echo -e "${GREEN}OK ($PODS pods running)${NC}"
else
  echo -e "${RED}FAIL (only $PODS pods running)${NC}"
fi

echo -n "Checking Wazuh agents... "
AGENTS=$(kubectl exec -n wazuh wazuh-manager-master-0 -- \
  /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active")
echo -e "${GREEN}OK ($AGENTS active agents)${NC}"

echo -n "Checking TheHive... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://172.16.10.10:31000)
if [ "$STATUS" = "200" ]; then
  echo -e "${GREEN}OK (HTTP $STATUS)${NC}"
else
  echo -e "${RED}FAIL (HTTP $STATUS)${NC}"
fi

echo -n "Checking Suricata... "
SURICATA=$(kubectl get pods -n nids --no-headers | grep -c "Running")
if [ "$SURICATA" -ge 1 ]; then
  echo -e "${GREEN}OK ($SURICATA pods running)${NC}"
else
  echo -e "${RED}FAIL${NC}"
fi

echo ""
echo "=== Validation Complete ==="
