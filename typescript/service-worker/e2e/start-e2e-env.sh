SSL_PATH="/etc/ssl"
CERT_PATH="${SSL_PATH}/cert.pem"
KEY_PATH="${SSL_PATH}/key.pem"
SW_PATH="/usr/share/nginx/html"
HTTP_PORT=80
HTTPS_PORT=443
SELENIUM_PORT=4444
SELENIUM_DEBUG_PORT=7900
HOST=$(ip addr show eth0 | grep 'inet\b' | awk '{print $2}' | cut -d/ -f1)

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
    -v "./dist-dev:${SW_PATH}" \
    -v "./certs:${SSL_PATH}" \
    -v "./e2e/docker/reverse-proxy:/etc/nginx/templates" \
    -p "${HTTP_PORT}:80" \
    -p "${HTTPS_PORT}:443" \
    -d \
    --name reverse-proxy \
    nginx:1.25.0

echo "Building Selenium Docker container..."
docker build -f \
    ./e2e/docker/selenium/Dockerfile \
    -t selenium \
    .

echo "Running Selenium Docker container..."
docker run --rm \
    --add-host "${IC_HOST}:${HOST}" \
    --add-host "${CANISTER_HOST}:${HOST}" \
    --shm-size="2g" \
    -p 4444:4444 \
    -p 7900:7900 \
    -d \
    --name selenium \
    selenium:latest

echo "Point WebDriver tests to http://localhost:${SELENIUM_PORT}"
echo "To see what is happening inside the container, head to http://localhost:${SELENIUM_DEBUG_PORT}/?autoconnect=1&resize=scale&password=secret"
echo "Canister is running at https://${CANISTER_HOST}"

echo "BASE_URL=https://${CANISTER_HOST}" >>.env
