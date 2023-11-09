#!/bin/bash

mkdir -p /var/lib/filebeat /var/log/filebeat

chown -R filebeat:filebeat /var/lib/filebeat /var/log/filebeat
chmod 0750 /var/lib/filebeat /var/log/filebeat

restorecon /var/lib/filebeat /var/log/filebeat
