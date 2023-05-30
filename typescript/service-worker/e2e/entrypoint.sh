#!/bin/bash

# Start DFX
dfx start --clean --background

# Deploy test canister
pushd ./e2e/canister
dfx deploy
REPLICA_PORT="$(dfx info replica-port)"
CANISTER_HOST="$(dfx canister id canister_frontend).local"
popd

# Generate SSL certificates
mkcert -cert-file /etc/ssl/cert.pem -key-file /etc/ssl/key.pem ${CANISTER_HOST} localhost 127.0.0.1 ::1

# Set up Nginx config
cat <<EOF >/etc/nginx/conf.d/default.conf
server {
    listen 80;
    listen [::]:80;
    server_name localhost ${CANISTER_HOST};

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/cert.pem;
    ssl_certificate_key /etc/ssl/key.pem;
    server_name localhost ${CANISTER_HOST};
    
    location / {
        root /usr/share/nginx/html;
        index index.html;
        try_files \$uri /index.html =404;
    }

    location /api/ {
        proxy_pass http://host.docker.internal:${REPLICA_PORT};
    }
}
EOF
service nginx restart

# Set up DNS hostname
echo -e "\n127.0.0.1 ${CANISTER_HOST}\n" >>/etc/hosts

# Stop DFX
dfx stop
