FROM --platform=linux/amd64 ubuntu:22.04

ENV DFX_VERSION=0.14.0
ENV NVM_VERSION=0.39.3
ENV MKCERT_VERSION=1.4.4
ENV NODEJS_VERSION=18

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    libunwind8 \
    libnss3-tools \
    curl \
    nginx

# Install NodeJS
RUN curl -fsSL "https://deb.nodesource.com/setup_${NODEJS_VERSION}.x" | bash - && \
    apt-get install -y nodejs

# Install Rust
ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path && \
    rustup target add wasm32-unknown-unknown

# Install mkcert
RUN curl -JLO "https://github.com/FiloSottile/mkcert/releases/download/v${MKCERT_VERSION}/mkcert-v${MKCERT_VERSION}-linux-amd64" && \
    chmod +x mkcert-v*-linux-amd64 && \
    cp mkcert-v*-linux-amd64 /usr/local/bin/mkcert && \
    mkcert -install

# Install DFX
RUN sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"

# Install NPM dependencies
COPY ./package.json ./package-lock.json ./
RUN npm ci

COPY . .

# Build SW bundle
RUN npm run build-dev && cp ./dist-dev/* /usr/share/nginx/html

ENTRYPOINT [ "./e2e/entrypoint.sh" ]
