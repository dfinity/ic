set -eEuo pipefail

if which docker 2>/dev/null; then
    docker login -u "$DOCKER_HUB_USER" -p "$DOCKER_HUB_PASSWORD_RO"
elif which docker-bin 2>/dev/null; then
    docker-bin login -u "$DOCKER_HUB_USER" -p "$DOCKER_HUB_PASSWORD_RO"
else
    echo "docker not installed"
    exit 1
fi
