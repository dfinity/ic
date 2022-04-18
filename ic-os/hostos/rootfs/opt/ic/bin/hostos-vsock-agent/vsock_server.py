import asyncio
import json
import logging
import socket
from collections import namedtuple

import vsock_agent


class AsyncVsockListener:
    """
    Async Vsock Server. Serves clients concurrently.

    Based on:
    https://docs.python.org/3.8/library/asyncio-stream.html#tcp-echo-client-using-streams
    """

    def __init__(self, port, conn_backlog=128):
        """Init the server with the given port and the connection backlog."""
        self.port = port
        self.conn_backlog = conn_backlog
        self.vsock_agent = vsock_agent.VsockAgent()

    async def _handle_connection(self, reader, writer):
        data = await reader.read(1024 * 1024)  # a message may be up to 1MiB in size
        message = data.decode()
        addr = writer.get_extra_info("peername")
        sender_cid = str(addr[0])
        task = None
        try:
            message_json = json.loads(message)
            logging.info("Received a message from %s: %s", addr, message_json)

            # As a sanity check, we request that the sender adds its own CID to the message
            # and that *must* match the addr[0] CID
            message_cid = str(message_json.get("sender_cid", "0"))

            if message_cid == sender_cid:
                response = json.dumps({"message": "accepted request", "status": "ok"})
                request = message_json.get("message")
                if request == "attach-hsm":
                    self.vsock_agent.handle_attach_request(sender_cid)
                elif request == "detach-hsm":
                    self.vsock_agent.handle_detach_request(sender_cid)
                elif request.startswith("set-node-id"):
                    node_id = request[12:-1]
                    self.vsock_agent.set_node_id(sender_cid, node_id)
                elif request == "join-success":
                    task = self.vsock_agent.handle_join_success(sender_cid)
                elif request.startswith("upgrade"):
                    data = request[8:-1].split()
                    Info = namedtuple("Info", ["url", "target_hash"])
                    info = Info(data[0], data[1])
                    self.vsock_agent.handle_upgrade_request(sender_cid, info)
                else:
                    logging.warning("Unsupported request from %s: %s", addr, request)
            else:
                logging.warning("Non-matching sender CID %s in message: %s", addr, message)
                response = json.dumps({"message": "invalid request", "status": "error"})

        except ValueError:
            logging.exception("Error processing message from %s: %s", addr, message)
            response = json.dumps({"message": "invalid request", "status": "error"})

        logging.debug("Sending response: %s", response)
        writer.write(response.encode("utf8"))
        await writer.drain()

        logging.debug("Closing the connection")
        writer.close()

        # Tie off any async tasks
        if task:
            await task

    async def main_loop(self):
        """Run the main async loop of the server on the configured port."""
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.bind((socket.VMADDR_CID_ANY, self.port))

        server = await asyncio.start_server(
            client_connected_cb=self._handle_connection,
            sock=sock,
        )

        addr = server.sockets[0].getsockname()
        logging.info(f"AsyncVsockListener listening on VMADDR_CID_ANY and port {addr[1]}")

        try:
            async with server:
                await server.serve_forever()
        except KeyboardInterrupt:  # pragma: no branch
            pass
        finally:
            logging.info("Shutting down the server")
            self.vsock_agent.terminate()
