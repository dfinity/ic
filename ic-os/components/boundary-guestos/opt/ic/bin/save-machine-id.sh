#!/bin/bash

if [ ! -e /boot/config/machine-id ]; then
    cp /etc/machine-id /boot/config/machine-id
fi
