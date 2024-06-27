set -exuo pipefail

pip3 install --ignore-installed -r requirements.txt

apt -yqq install rclone

"${CI_PROJECT_DIR}"/gitlab-ci/src/artifacts/rclone_download.py --git-rev "$CI_COMMIT_SHA" \
    --remote-path=release --out="artifacts/release"

gunzip artifacts/release/ic-rosetta-api.gz
chmod +x artifacts/release/ic-rosetta-api

pushd "$(mktemp -d)"
cp "$CI_PROJECT_DIR"/artifacts/release/ic-rosetta-api .

IMAGE_NAME="ghcr.io/dfinity/rosetta-api"

docker build \
    --build-arg RELEASE="$CI_COMMIT_SHA" \
    -f "$CI_PROJECT_DIR"/rs/rosetta-api/Dockerfile \
    -t "$IMAGE_NAME":"$CI_COMMIT_SHA" .
popd

docker run --rm "$IMAGE_NAME":"$CI_COMMIT_SHA" --help

ROSETTA_API_DATE=$(date +"%Y%m%d")
ROSETTA_API_VERSION=$(grep -e '^version' "$CI_PROJECT_DIR"/rs/rosetta-api/Cargo.toml | sed -e 's|^version[ ]*=[ ]*"\([^"]*\)"|\1|g')

docker tag "$IMAGE_NAME":"$CI_COMMIT_SHA" "$IMAGE_NAME":"$ROSETTA_API_DATE"
docker tag "$IMAGE_NAME":"$CI_COMMIT_SHA" "$IMAGE_NAME":v"$ROSETTA_API_VERSION"
docker tag "$IMAGE_NAME":"$CI_COMMIT_SHA" "$IMAGE_NAME":latest

docker push "$IMAGE_NAME":"$CI_COMMIT_SHA"
docker push "$IMAGE_NAME":"$ROSETTA_API_DATE"
docker push "$IMAGE_NAME":v"$ROSETTA_API_VERSION"
docker push "$IMAGE_NAME":latest
