from __future__ import annotations

import argparse
import http.client
import http.server
import io
import json
import re
import ssl
from http.server import BaseHTTPRequestHandler as BaseHandler
from http.server import HTTPServer

STATUS_OK = 200
STATUS_NOT_FOUND = 404

CONTENT_TYPE_TEXT_PLAIN = "text/plain"
CONTENT_TYPE_JSON = "application/json"


class Handler(BaseHandler):
    def __init__(
        self,
        *args,
        cache,
        hostname,
        port,
        acme_host,
        acme_port,
        **kwargs,
    ):
        self.cache = cache
        self.hostname = hostname
        self.port = port
        self.acme_host = acme_host
        self.acme_port = acme_port

        super().__init__(*args, **kwargs)

    def write(
        self,
        body: bytes,
        status_code: int = STATUS_OK,
        content_type: str = CONTENT_TYPE_TEXT_PLAIN,
        headers: list[tuple[str, str]] = None,
    ):
        # Status
        self.send_response(status_code)

        # Headers
        if headers is None:
            headers = [
                ("Content-Length", len(body)),
                ("Content-Type", content_type),
            ]

        for header, value in headers:
            self.send_header(header, value)

        self.end_headers()

        # Body
        self.wfile.write(body)

    def write_response(self, response: http.client.HTTPResponse):
        # Status
        self.send_response(response.status)

        # Headers
        for header, value in response.getheaders():
            self.send_header(header, value)

        self.end_headers()

        # Body
        self.wfile.write(response.read())

    def not_found(self):
        self.write(b"Not found", status_code=STATUS_NOT_FOUND)

    #
    # Utilities
    #

    def get_nonce(self):
        # Create a custom SSL context with certificate verification disabled
        conn = http.client.HTTPSConnection(
            host=self.acme_host,
            port=self.acme_port,
            context=ssl._create_unverified_context(),
        )

        # Send the request to the upstream server
        conn.request("HEAD", "/nonce-plz")

        # Get the response from the upstream server
        response = conn.getresponse()

        for header, value in response.getheaders():
            if header == "Replay-Nonce":
                return value

        raise Exception("unable to obtain nonce")

    #
    # Handlers
    #

    def proxy_partial(self, method: str):
        # Create a custom SSL context with certificate verification disabled
        conn = http.client.HTTPSConnection(
            host=self.acme_host,
            port=self.acme_port,
            context=ssl._create_unverified_context(),
        )

        # Read the request body from the client's request
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Extract client's request headers
        headers = {key: value for key, value in self.headers.items()}

        # Send the request to the upstream server
        conn.request(method, self.path, body=body, headers=headers)

        # Get the response from the upstream server
        return conn.getresponse()

    def proxy(self, method: str):
        return self.write_response(self.proxy_partial(method))

    def dir(self):
        self.write(
            json.dumps(
                {
                    "keyChange": f"https://{self.hostname}:{self.port}/rollover-account-key",
                    "meta": {
                        "externalAccountRequired": False,
                        "termsOfService": "data:text/plain,OK",
                    },
                    "newAccount": f"https://{self.hostname}:{self.port}/sign-me-up",
                    "newNonce": f"https://{self.hostname}:{self.port}/nonce-plz",
                    "newOrder": f"https://{self.hostname}:{self.port}/order-plz",
                    "revokeCert": f"https://{self.hostname}:{self.port}/revoke-cert",
                }
            ).encode("utf-8"),
            content_type=CONTENT_TYPE_JSON,
        )

    def new_order(self):
        # Read the request body from the client's request
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Replace request body
        self.rfile = io.BytesIO(body)

        # Check for cache hit
        data = json.loads(body)
        cache_key = data["payload"]

        if cache_key in self.cache:
            headers = cache[cache_key]["headers"]

            # Replace Replay-Nonce
            headers = [(k, v) for (k, v) in headers if k != "Replay-Nonce"]
            headers.append(("Replay-Nonce", self.get_nonce()))

            return self.write(
                body=cache[cache_key]["body"],
                status_code=cache[cache_key]["status_code"],
                headers=headers,
            )

        # Cache-miss, proxy to upstream
        response = self.proxy_partial("POST")

        content_length = int(response.headers.get("Content-Length", 0))
        body = response.read(content_length)

        # Store request for later re-use
        cache[cache_key] = {
            "body": body,
            "status_code": response.status,
            "headers": response.getheaders(),
        }

        return self.write(
            body=cache[cache_key]["body"],
            status_code=cache[cache_key]["status_code"],
            headers=cache[cache_key]["headers"],
        )

    def cert(self):
        response = self.proxy_partial("POST")

        # Body
        body = response.read()

        # Headers
        headers = response.getheaders()

        # Remove Transfer-Encoding header
        headers = [(k, v) for (k, v) in headers if k != "Transfer-Encoding"]

        # Update Content-Type
        headers = [(k, v) for (k, v) in headers if k != "Content-Type"]
        headers.append(("Content-Type", "text/plain"))

        # Update Content-Length
        headers = [(k, v) for (k, v) in headers if k != "Content-Length"]
        headers.append(("Content-Length", f"{len(body)}"))

        return self.write(
            body=body,
            status_code=response.status,
            headers=headers,
        )

    #
    # Routes
    #

    def route(self, route_handlers, default=None):
        for route, handler in route_handlers.items():
            match = re.search(route, self.path)
            if not match:
                continue

            if isinstance(match.groups(), tuple):
                return handler(*match.groups())

            return handler()

        if default is not None:
            return default()

        return self.not_found()

    def do_HEAD(self):
        return self.route({}, default=lambda: self.proxy("HEAD"))

    def do_GET(self):
        return self.route(
            {
                r"^/dir$": self.dir,
            },
            default=lambda: self.proxy("GET"),
        )

    def do_POST(self):
        return self.route(
            {
                r"^/order-plz$": self.new_order,
                r"^/certZ/\w+$": self.cert,
            },
            default=lambda: self.proxy("POST"),
        )


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Caching proxy server")
    parser.add_argument("--hostname", help="Assumed Hostname")
    parser.add_argument("--port", type=int, help="Proxy port")
    parser.add_argument("--acme_host", help="ACME host")
    parser.add_argument("--acme_port", type=int, help="ACME port")
    parser.add_argument("--tls_key", help="TLS Private Key")
    parser.add_argument("--tls_cert", help="TLS Certificate")
    cli = parser.parse_args()

    cache = {}

    # Load the TLS key-pair into an SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(cli.tls_cert, cli.tls_key)

    httpd = HTTPServer(
        ("", cli.port),
        lambda *args, **kwargs: Handler(
            *args,
            cache=cache,
            hostname=cli.hostname,
            port=cli.port,
            acme_host=cli.acme_host,
            acme_port=cli.acme_port,
            **kwargs,
        ),
    )

    httpd.socket = ssl_context.wrap_socket(
        httpd.socket,
    )

    httpd.serve_forever()
