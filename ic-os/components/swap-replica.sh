#!/bin/bash

set -x

chmod +x "${1}"
mount --bind "${1}" /opt/ic/bin/replica
