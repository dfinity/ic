#!/bin/sh
##########################################################################################
############ Configures Universal VM to run static file serving on HTTP ##################
##########################################################################################

mkdir web
cd web
cp /config/registry.tar .
chmod -R 755 ./

docker load -i /config/static-file-server.tar
docker run -d \
    -v "$(pwd)":/web \
    -p 80:8080 \
    static-file-server:image
