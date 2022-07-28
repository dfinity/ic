#!/bin/bash

set -e

IP=$(ip -brief -family inet address show scope global | grep -w UP | grep -o -m1 "[0-9]*\.[0-9*\.[0-9]*\.[0-9]*")
sed -i "s/LISTEN_ADDRESS/${IP}/" /run/ic-node/etc/nginx/conf.d/cgi.conf
