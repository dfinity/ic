#!/bin/bash

set -e

# Completes the recovery process by downloading and applying the recovery artifacts

echo "Starting GuestOS recovery process..."
echo "Downloading recovery artifacts..."
# ... 
# download ic_registry_local_store.tar.zst and cup.proto

echo "Preparing recovery artifacts..."
OWNER_UID=$(sudo stat -c '%u' /var/lib/ic/data/ic_registry_local_store);
GROUP_UID=$(sudo stat -c '%g' /var/lib/ic/data/ic_registry_local_store);

mkdir ic_registry_local_store;
tar zxf ic_registry_local_store.tar.zst -C ic_registry_local_store;
sudo chown -R "$OWNER_UID:$GROUP_UID" ic_registry_local_store;

OWNER_UID=$(sudo stat -c '%u' /var/lib/ic/data/cups);
GROUP_UID=$(sudo stat -c '%g' /var/lib/ic/data/cups);
sudo chown -R "$OWNER_UID:$GROUP_UID" cup.proto;

echo "Applying recovery artifacts..."
echo "Syncing ic_registry_local_store to target location..."
sudo rsync -a --delete ic_registry_local_store/ /var/lib/ic/data/ic_registry_local_store/;
echo "Copying cup.proto to target location..."
sudo cp cup.proto /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb;

echo "Recovery artifacts applied successfully"

echo "Restarting services..."
sudo systemctl restart setup-permissions || true ;
# TODO: discuss service restarts: we can either restart the ic-replica service here or have the service itself come before ic-replica.service
# sudo systemctl start ic-replica;
# sudo systemctl status ic-replica;

echo "GuestOS recovery process completed"
