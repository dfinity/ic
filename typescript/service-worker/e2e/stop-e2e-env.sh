echo "Stopping DFX..."
dfx stop

echo "Stopping reverse proxy Docker container..."
docker stop sw-reverse-proxy

echo "Stopping Selenium Docker container..."
docker stop sw-selenium
