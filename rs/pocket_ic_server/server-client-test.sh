
$SERVER_BIN 2>&1 &
sleep 5

# This works:
curl http://127.0.0.1:3000/index.html -v --silent

# This doesn't:
$CLIENT_BIN