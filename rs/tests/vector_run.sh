#!/bin/sh
set -e

echo "Waiting for /etc/vector/config/spawn_vector..."
while [ ! -f /etc/vector/config/spawn_vector ]; do
  sleep 1
done

echo "spawn_vector detected. Starting Vector..."
exec vector -w --config-dir /etc/vector/config 
