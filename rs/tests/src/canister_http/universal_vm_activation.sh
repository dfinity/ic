#!/bin/sh
##########################################################################################
############ Configures Universal VM to run httpbin service on HTTP and HTTPS ############
##########################################################################################

# 1 - read ipv6 and ipv4 of current node
ipv6=""
while true; do
    ipv6=$(ip -6 address | grep "scope global dynamic" | awk '{$1=$1};1' | awk -F '[ \t]+|/' '{print $2}')
    if [[ $ipv6 == '' ]]; then
        sleep 5s
        echo "IPv6 not found. Retrying in 5 seconds ..."
    else
        echo "Found IPv6 $ipv6"
        break
    fi
done
export ipv6
echo "IPv6 is $ipv6"

ipv4=""
while true; do
    ipv4=$(ip -4 address | grep "scope global dynamic" | awk '{$1=$1};1' | awk -F '[ \t]+|/' '{print $2}')
    if [[ $ipv4 == '' ]]; then
        sleep 5s
        echo "IPv4 not found. Retrying in 5 seconds ..."
    else
        echo "Found IPv4 $ipv4"
        break
    fi
done
export ipv4
echo "IPv4 is $ipv4"

# 2 - setting up httpbin on port 80
docker run \
    --rm \
    -d \
    -p 20080:80 \
    --name httpbin \
    registry.gitlab.com/dfinity-lab/open/public-docker-registry/kennethreitz/httpbin

# 3 - generate ipv6 service cert with root cert and key, using `minica`
mkdir certs
cd certs
cp /config/cert.pem minica.pem
cp /config/key.pem minica-key.pem
chmod -R 755 ./

echo "Making certs directory in $(pwd)"
docker run \
    -v "$(pwd)":/output \
    registry.gitlab.com/dfinity-lab/open/public-docker-registry/ryantk/minica \
    -ip-addresses="$ipv6"

mv $ipv6 ipv6 # updateing service certificate folder name so it can be fed to ssl-proxy container
chmod -R 755 ipv6

# 4 - initiate `ssl-proxy` container on port 443, attach it to `httpbin` container, supply the service
# cert and key generated in step #2.
docker run \
    --rm \
    -d \
    --name ssl-proxy \
    --link httpbin \
    -p 20443:443 \
    -v "$(pwd)/ipv6":/etc/nginx/certs \
    -e TARGET_HOST="httpbin" \
    -e TARGET_PORT="80" \
    -e SSL_PORT="443" \
    -e DOMAIN="[$ipv6]" \
    registry.gitlab.com/dfinity-lab/open/public-docker-registry/fsouza/docker-ssl-proxy
