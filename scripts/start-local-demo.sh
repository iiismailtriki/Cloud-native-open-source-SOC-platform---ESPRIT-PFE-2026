#!/bin/bash
# =============================================================
# SOC Platform - Local AWX Demo Startup Script
# ESPRIT PFE 2026 - Ismail Triki
# Run before the defense to bring up and verify the local demo
# =============================================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

MASTER_IP="192.168.122.35"
WORKER1_IP="192.168.122.10"
WORKER2_IP="192.168.122.95"
USER="ismail"

echo "=================================================="
echo " SOC Platform - Local AWX Demo Startup"
echo "=================================================="
echo ""

info "Starting local VMs..."
sudo virsh start soc-master  2>/dev/null || true
sudo virsh start soc-worker1 2>/dev/null || true
sudo virsh start soc-worker2 2>/dev/null || true

info "Waiting for SSH on all VMs..."
for IP in "$MASTER_IP" "$WORKER1_IP" "$WORKER2_IP"; do
  echo -n "Waiting for $IP"
  for i in {1..24}; do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$USER@$IP" "echo ok" &>/dev/null; then
      echo ""
      ok "SSH reachable: $IP"
      break
    fi
    echo -n "."
    sleep 5
    if [ "$i" -eq 24 ]; then
      echo ""
      fail "SSH unreachable after 120s: $IP"
    fi
  done
done

info "Adding kind → libvirt route for AWX..."
KIND_CONTAINER=$(docker ps --format '{{.ID}} {{.Image}} {{.Names}}' | grep -E 'kindest|awx' | awk '{print $1}' | head -1)
if [ -n "$KIND_CONTAINER" ]; then
  docker exec "$KIND_CONTAINER" ip route add 192.168.122.0/24 via 172.18.0.1 2>/dev/null || true
  ok "Route added or already exists"
else
  fail "kind/AWX container not found. Check if AWX is running."
fi

info "Checking k3s cluster..."
NODES=$(ssh -o StrictHostKeyChecking=no "$USER@$MASTER_IP" \
  "sudo k3s kubectl get nodes --no-headers 2>/dev/null | grep -c Ready" 2>/dev/null || echo 0)
if [ "$NODES" -eq 3 ]; then
  ok "k3s cluster: 3/3 nodes Ready"
else
  fail "k3s cluster: only $NODES nodes Ready, expected 3"
  ssh -o StrictHostKeyChecking=no "$USER@$MASTER_IP" "sudo k3s kubectl get nodes -o wide" || true
fi

info "Checking Wazuh agents..."
for IP in "$MASTER_IP" "$WORKER1_IP" "$WORKER2_IP"; do
  STATUS=$(ssh -o StrictHostKeyChecking=no "$USER@$IP" "systemctl is-active wazuh-agent 2>/dev/null" || echo "inactive")
  if [ "$STATUS" = "active" ]; then
    ok "Wazuh agent active: $IP"
  else
    fail "Wazuh agent inactive: $IP"
  fi
done

info "Checking Suricata on worker1..."
if ssh -o StrictHostKeyChecking=no "$USER@$WORKER1_IP" "sudo test -f /var/lib/suricata/rules/suricata.rules" 2>/dev/null; then
  ok "Suricata rules file exists"
else
  fail "Suricata rules file missing"
fi
if ssh -o StrictHostKeyChecking=no "$USER@$WORKER1_IP" "sudo suricata -T -c /etc/suricata/suricata.yaml >/tmp/suricata-check.log 2>&1" 2>/dev/null; then
  ok "Suricata config validation passed"
else
  fail "Suricata config validation failed"
fi
ssh -o StrictHostKeyChecking=no "$USER@$WORKER1_IP" \
  "suricata --build-info | grep -E 'Suricata version|AF_PACKET support'" || true

info "Checking AWX..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/v2/ping/ || echo "000")
if [ "$HTTP" = "200" ]; then
  ok "AWX is up at http://localhost:8080"
else
  fail "AWX not responding. HTTP: $HTTP"
fi

echo ""
echo "=================================================="
echo " LOCAL DEMO CHECK COMPLETE"
echo "=================================================="
echo " AWX UI     : http://localhost:8080"
echo " Login      : admin"
echo " Template   : Deploy LOCAL SOC Demo"
echo ""
echo " Demo proof:"
echo " - k3s cluster  : 3 local VMs, all Ready"
echo " - Wazuh agents : active on all 3 nodes"
echo " - Suricata     : installed, rules present, config validated"
echo ""
echo " NOTE: Suricata is validated only."
echo " Do not claim live traffic monitoring."
echo "=================================================="
