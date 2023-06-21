source .env

echo "Compiling typescript code..."
rm -rf ./e2e/dist
npx tsc -p ./e2e/tsconfig.json

echo "Running e2e tests..."
node ./e2e/dist/specs/asset-loading.spec.mjs ${BASE_URL} ${SW_PATH} ${CURRENT_SW_PATH} ${LATEST_SW_PATH} ${PREVIOUS_SW_PATH}
node ./e2e/dist/specs/broken-downgrade.spec.mjs ${BASE_URL} ${SW_PATH} ${BROKEN_UPGRADE_SW_PATH} ${BROKEN_DOWNGRADE_SW_PATH}
