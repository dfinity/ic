import socket


class VsockStream:
    """Vsock (stream) client."""

    def __init__(self, conn_tmo=5):
        """Create a new vsock client."""
        self.conn_tmo = conn_tmo

    def connect(self, endpoint):
        """Connect to the remote endpoint."""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)

    def send_data(self, data):
        """Send data to the remote endpoint."""
        self.sock.sendall(data)
        self.sock.close()
