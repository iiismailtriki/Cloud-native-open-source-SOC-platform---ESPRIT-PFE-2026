#!/bin/bash
echo "=== SOC Recovery - $(date) ==="

# Fix svclb pods
echo "[1] Recycling svclb pods..."
kubectl delete pods -n kube-system $(kubectl get pods -n kube-system | grep svclb-wazuh | awk '{print $1}') 2>/dev/null
sleep 30

# Fix Cortex if down
echo "[2] Checking Cortex..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://172.16.10.10:9001)
if [ "$STATUS" != "200" ]; then
  ssh socadmin@172.16.10.10 "sudo docker stop cortex-cortex-1 cortex-elasticsearch-1 && sudo docker rm cortex-cortex-1 cortex-elasticsearch-1 && cd ~/cortex && sudo docker compose up -d"
fi

# Fix Shuffle if down
echo "[3] Checking Shuffle..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://172.16.10.10:3001)
if [ "$STATUS" != "200" ]; then
  ssh socadmin@172.16.10.10 "cd ~/Shuffle && sudo docker compose up -d"
fi

# Fix TheHive if down
echo "[4] Checking TheHive..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://172.16.10.10:31000)
if [ "$STATUS" != "200" ]; then
  kubectl rollout restart deployment/thehive -n thehive
  sleep 60
fi

# Renew TheHive API key
echo "[5] Renewing TheHive API key..."
NEW_KEY=$(curl -s -u "admin@thehive.local:secret" \
  -X POST http://172.16.10.10:31000/api/v1/user/soc@soc.local/key/renew)
if [ ! -z "$NEW_KEY" ]; then
  kubectl create secret generic thehive-soc-apikey \
    -n thehive --from-literal=api-key="$NEW_KEY" \
    --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null
  kubectl exec -n wazuh wazuh-manager-worker-0 -- bash -c \
    "sed -i 's|<api_key>.*</api_key>|<api_key>$NEW_KEY</api_key>|' /var/ossec/etc/ossec.conf" 2>/dev/null
fi

# Fix custom-thehive permissions
echo "[6] Fixing permissions..."
kubectl exec -n wazuh wazuh-manager-worker-0 -- bash -c \
  "chown root:wazuh /var/ossec/integrations/custom-thehive* 2>/dev/null && chmod 750 /var/ossec/integrations/custom-thehive* 2>/dev/null"

echo "=== Done - $(date) ==="
