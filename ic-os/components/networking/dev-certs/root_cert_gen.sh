#!/bin/bash

# Checks whether docker is available. If not, prompt message to install
if ! docker info; then
    echo "docker not available. Please install docker locally! \
    For example: $(sudo apt install docker)"
fi

# Generate certificate and signing key for foo.bar domain using `minica` under current directory.
# Since there isn't root cert (minica.pem) and root signing key (minica-key.pem) under
# current directory, `minica` will automatically generate them.
docker run -it -v "$(pwd)"/:/output ryantk/minica --domains foo.bar

# Discard the certificate and key for foo.bar domain.  We only need root certificate and key.
# Copy them to target directory, and change access mode.
sudo rm -rf foo.bar
sudo chmod 755 minica.pem
sudo chmod 755 minica-key.pem
