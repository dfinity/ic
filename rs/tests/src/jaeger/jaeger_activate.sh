#!/bin/sh

docker load -i /config/jaeger.tar
docker run -d --name jaeger \
    -e COLLECTOR_OTLP_ENABLED=true \
    -e SPAN_STORAGE_TYPE=badger \
    -e BADGER_DIRECTORY_VALUE=/badger/data \
    -e BADGER_DIRECTORY_KEY=/badger/key \
    -p 4317:4317 \
    -p 16686:16686 \
    jaegertracing/all-in-one:1.58
