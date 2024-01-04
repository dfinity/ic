FROM ubuntu:22.04
# https://github.com/docker-library/docs/pull/1710/files/e57957756b61481bbd586d08c2fbe565753518c0
# For why this line is commented
RUN apt-get update && apt-get install -y openssl && apt clean && rm -rf /var/lib/apt/lists/*

COPY ./build-dir-service-discovery/multiservice_discovery /usr/bin/multiservice-discovery

ENTRYPOINT ["/usr/bin/multiservice-discovery"]
