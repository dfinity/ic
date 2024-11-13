#!/bin/bash

VECTOR_DIR=/var/lib/vector

if [ ! -d ${VECTOR_DIR} ]; then
    mkdir -p ${VECTOR_DIR}
fi

chown -R vector:vector ${VECTOR_DIR}
chmod 0750 ${VECTOR_DIR}

restorecon ${VECTOR_DIR}
