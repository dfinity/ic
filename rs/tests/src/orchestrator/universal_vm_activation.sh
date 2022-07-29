#!/bin/sh
##########################################################################################
############ Configures Universal VM to run static file serving on HTTP ##################
##########################################################################################

mkdir web
cd web
cp /config/registry.tar .
chmod -R 755 ./

docker run -d \
    -v "$(pwd)":/web \
    -p 80:8080 \
    halverneus/static-file-server:latest
