SELENIUM_PORT=4444
SELENIUM_DEBUG_PORT=7900
HOST=$(ip addr show eth0 | grep 'inet\b' | awk '{print $2}' | cut -d/ -f1)
SW_PATH_PREFIX="./tmp/sw"
SW_PATH_POSTFIX="package/dist-dev"
CURRENT_SW_PATH="${SW_PATH_PREFIX}/current"

SSL_PATH="/etc/ssl"
CERT_PATH="${SSL_PATH}/cert.pem"
KEY_PATH="${SSL_PATH}/key.pem"
SW_PATH="/usr/share/nginx/html"
SW_SRC_PATH="/opt/sw"
HTTP_PORT=80
HTTPS_PORT=443

download_sw() {
    SW_VERSION=$1
    SW_TARBALL=$(npm view @dfinity/service-worker@${SW_VERSION} dist.tarball)
    SW_DIR="${SW_PATH_PREFIX}/${SW_VERSION}"

    echo "Downloading service worker v${SW_VERSION}..."
    mkdir -p ${SW_DIR}
    curl -L ${SW_TARBALL} -o ${SW_DIR}/service-worker.tgz
    tar xfvz ${SW_DIR}/service-worker.tgz -C ${SW_DIR}
}

LATEST_SW_VERSION=$(npm view @dfinity/service-worker version)
PREVIOUS_SW_VERSION=$(npm view @dfinity/service-worker versions --json | jq --raw-output .[-2])
BROKEN_UPGRADE_SW_VERSION="1.6.0"
BROKEN_DOWNGRADE_SW_VERSION="1.5.2"

download_sw ${LATEST_SW_VERSION}
download_sw ${PREVIOUS_SW_VERSION}
download_sw ${BROKEN_UPGRADE_SW_VERSION}
download_sw ${BROKEN_DOWNGRADE_SW_VERSION}

echo "Building current service worker..."
npm run build-dev
mkdir -p ${CURRENT_SW_PATH}
cp ./dist-dev/* ${CURRENT_SW_PATH}

echo "Running DFX..."
dfx start --background || echo "DFX is already running..."

pushd ./e2e/canister
echo "Deploying canister..."
dfx deploy

echo "Getting canister ID..."
CANISTER_ID=$(dfx canister id canister_frontend)
popd # ./e2e/canister

echo "Getting DFX replica port..."
REPLICA_PORT=$(dfx info replica-port)
IC_HOST="ic0.local"
CANISTER_HOST="${CANISTER_ID}.${IC_HOST}"
DFX_HOST="http://${HOST}:${REPLICA_PORT}"

echo "Copying root CA..."
cp $(mkcert -CAROOT)/* ./certs/

echo "Running reverse proxy Docker container..."
docker run --rm \
    -e CANISTER_HOST="${CANISTER_HOST}" \
    -e CERT_PATH="${CERT_PATH}" \
    -e KEY_PATH="${KEY_PATH}" \
    -e SW_PATH="${SW_PATH}" \
    -e DFX_HOST="${DFX_HOST}" \
    -v "${SW_PATH_PREFIX}:${SW_SRC_PATH}" \
    -v "./certs:${SSL_PATH}" \
    -v "./e2e/docker/reverse-proxy:/etc/nginx/templates" \
    -p "${HTTP_PORT}:80" \
    -p "${HTTPS_PORT}:443" \
    -d \
    --name sw-reverse-proxy \
    nginx:1.25.0

echo "Building Selenium Docker container..."
docker build -f \
    ./e2e/docker/selenium/Dockerfile \
    -t sw-selenium \
    .

echo "Running Selenium Docker container..."
docker run --rm \
    --add-host "${IC_HOST}:${HOST}" \
    --add-host "${CANISTER_HOST}:${HOST}" \
    --shm-size="2g" \
    -p 4444:4444 \
    -p 7900:7900 \
    -d \
    --name sw-selenium \
    sw-selenium:latest

echo "Point WebDriver tests to http://localhost:${SELENIUM_PORT}"
echo "To see what is happening inside the container, head to http://localhost:${SELENIUM_DEBUG_PORT}/?autoconnect=1&resize=scale&password=secret"
echo "Canister is running at https://${CANISTER_HOST}"

cat <<EOF >.env
BASE_URL=https://${CANISTER_HOST}
CURRENT_SW_PATH=${SW_SRC_PATH}/current
LATEST_SW_PATH=${SW_SRC_PATH}/${LATEST_SW_VERSION}/${SW_PATH_POSTFIX}
PREVIOUS_SW_PATH=${SW_SRC_PATH}/${PREVIOUS_SW_VERSION}/${SW_PATH_POSTFIX}
BROKEN_UPGRADE_SW_PATH=${SW_SRC_PATH}/${BROKEN_UPGRADE_SW_VERSION}/${SW_PATH_POSTFIX}
BROKEN_DOWNGRADE_SW_PATH=${SW_SRC_PATH}/${BROKEN_DOWNGRADE_SW_VERSION}/${SW_PATH_POSTFIX}
SW_PATH=${SW_PATH}
EOF
