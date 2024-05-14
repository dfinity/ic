#!/bin/sh

docker load -i /config/image.tar
docker run -d --name jaeger \
    -e COLLECTOR_OTLP_ENABLED=true \
    -p 4317:4317 \
    -p 16686:16686 \
    jaegertracing/all-in-one
