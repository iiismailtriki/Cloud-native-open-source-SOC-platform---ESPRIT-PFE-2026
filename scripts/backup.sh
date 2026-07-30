#!/bin/bash
DATE=$(date +%Y%m%d)
BACKUP_DIR="/home/socadmin/backups/$DATE"
mkdir -p $BACKUP_DIR

echo "=== Backup - $(date) ==="

# TheHive API key
kubectl get secret thehive-soc-apikey -n thehive -o yaml > $BACKUP_DIR/thehive-secret.yaml

# Wazuh configs
kubectl exec -n wazuh wazuh-manager-worker-0 -- \
  cat /var/ossec/etc/ossec.conf > $BACKUP_DIR/wazuh-ossec.conf 2>/dev/null

kubectl exec -n wazuh wazuh-manager-worker-0 -- \
  cat /var/ossec/etc/rules/local_ssh_bruteforce.xml > $BACKUP_DIR/local_ssh_bruteforce.xml 2>/dev/null

# TheHive deployment
kubectl get deployment thehive -n thehive -o yaml > $BACKUP_DIR/thehive-deployment.yaml

echo "Backup saved to $BACKUP_DIR"
ls $BACKUP_DIR
