#!/bin/bash
# TheHive SOC org setup script
# Run this after TheHive restart to restore SOC org, user and API key
# API key is also stored in Wazuh ConfigMap wazuh-conf-m5756d8fbh

set -e
BASE="http://172.16.10.10:31000"
FIXED_API_KEY="8nR1X6pEp1t8ggQJo4MCyUd05a+hxkYk"

echo "[TheHive Setup] Waiting for TheHive to be ready..."
for i in $(seq 1 30); do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/api/status" 2>/dev/null)
    if [ "$STATUS" = "200" ]; then
        echo "[TheHive Setup] TheHive is ready."
        break
    fi
    sleep 5
done

echo "[TheHive Setup] Logging in as admin..."
curl -sk -c /tmp/thehive_setup_cookie.txt -X POST "$BASE/api/login" \
    -H "Content-Type: application/json" \
    -d '{"user":"admin@thehive.local","password":"secret"}' > /dev/null 2>&1

echo "[TheHive Setup] Creating SOC organization..."
curl -sk -b /tmp/thehive_setup_cookie.txt -X POST "$BASE/api/v1/organisation" \
    -H "Content-Type: application/json" \
    -d '{"name":"SOC","description":"SOC Security Operations Center"}' > /dev/null 2>/dev/null || true

echo "[TheHive Setup] Creating soc@soc.local user..."
curl -sk -b /tmp/thehive_setup_cookie.txt -X POST "$BASE/api/v1/user" \
    -H "Content-Type: application/json" \
    -d '{"login":"soc@soc.local","name":"SOC Analyst","organisation":"SOC","profile":"analyst"}' > /dev/null 2>/dev/null || true

echo "[TheHive Setup] Setting password..."
curl -sk -b /tmp/thehive_setup_cookie.txt -X POST "$BASE/api/v1/user/soc@soc.local/password/set" \
    -H "Content-Type: application/json" \
    -d '{"password":"SecretPassword"}' > /dev/null 2>/dev/null || true

echo "[TheHive Setup] Setting API key..."
CURR_KEY=$(curl -sk -b /tmp/thehive_setup_cookie.txt -X POST "$BASE/api/v1/user/soc@soc.local/key/renew" \
    -H "Content-Type: application/json" 2>/dev/null | tr -d '"')

echo "[TheHive Setup] Current API key: $CURR_KEY"
echo "[TheHive Setup] Expected key:    $FIXED_API_KEY"

echo "[TheHive Setup] Verifying with case creation..."
RESULT=$(curl -sk -H "Authorization: Bearer $CURR_KEY" -X POST "$BASE/api/v1/case" \
    -H "Content-Type: application/json" \
    -d '{"title":"[INIT] SOC Setup Verification","description":"Auto-created to verify TheHive SOC org is working.","severity":1,"tags":["setup"],"flag":false}' 2>/dev/null)
CASE_NUM=$(echo "$RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('number','ERROR'))" 2>/dev/null)
echo "[TheHive Setup] Test case created: #$CASE_NUM"

if [ "$CURR_KEY" != "$FIXED_API_KEY" ]; then
    echo ""
    echo "=== ACTION REQUIRED ==="
    echo "New API key generated: $CURR_KEY"
    echo "Update Wazuh config with new key by running:"
    echo "  kubectl patch configmap wazuh-conf-m5756d8fbh -n wazuh --type=merge -p \"{\\\"data\\\":{...}}\""
    echo "Or run this on both manager pods:"
    echo "  kubectl exec -n wazuh wazuh-manager-master-0 -- sed -i 's|<api_key>.*</api_key>|<api_key>$CURR_KEY</api_key>|g' /var/ossec/etc/ossec.conf"
    echo "  kubectl exec -n wazuh wazuh-manager-worker-0 -- sed -i 's|<api_key>.*</api_key>|<api_key>$CURR_KEY</api_key>|g' /var/ossec/etc/ossec.conf"
fi

echo "[TheHive Setup] Done."
