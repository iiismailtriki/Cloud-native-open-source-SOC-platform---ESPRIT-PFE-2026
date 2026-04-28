#!/bin/bash
set -e
echo "=== SOC Platform Deployment ==="

echo "[1/4] Running Ansible playbook..."
ansible-playbook -i ansible/inventory/hosts.ini ansible/site.yml

echo "[2/4] Verifying Kubernetes namespaces..."
for ns in wazuh nids thehive; do
  kubectl get namespace $ns &>/dev/null || kubectl create namespace $ns
  echo "  namespace/$ns OK"
done

echo "[3/4] Checking Wazuh stack..."
kubectl rollout status statefulset/wazuh-manager-master -n wazuh --timeout=120s
kubectl rollout status statefulset/wazuh-indexer -n wazuh --timeout=120s

echo "[4/4] Running validation..."
./scripts/validate.sh

echo "=== Deployment Complete ==="
