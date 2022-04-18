#!/usr/local/bin/env python3
import argparse
import asyncio
import logging
import sys

import vsock_client
import vsock_server


def client_handler(args):
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    client = vsock_client.VsockStream()
    endpoint = (args.cid, args.port)
    client.connect(endpoint)
    msg = "Hello, world!"
    client.send_data(msg.encode())


def server_handler(args):
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # We use an async server to support multiple clients sending requests in parallel
    server = vsock_server.AsyncVsockListener(args.port)
    asyncio.run(server.main_loop())


def main():
    parser = argparse.ArgumentParser(prog="vsock-sample")
    parser.add_argument(
        "--version",
        action="version",
        help="Prints version information.",
        version="%(prog)s 0.1.0",
    )
    subparsers = parser.add_subparsers(title="options")

    client_parser = subparsers.add_parser("client", description="Client", help="Connect to a given cid and port.")
    client_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")
    client_parser.add_argument("cid", type=int, help="The remote endpoint CID.")
    client_parser.add_argument("port", type=int, help="The remote endpoint port.")
    client_parser.set_defaults(func=client_handler)

    server_parser = subparsers.add_parser("server", description="Server", help="Listen on a given port.")
    server_parser.add_argument(
        "--port",
        type=int,
        default=19090,
        help="The local port to listen on.",
    )
    server_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    server_parser.set_defaults(func=server_handler)

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
