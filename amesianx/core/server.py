"""HTTP server classes: DualStackHTTPServer and ThreadedDualStackServer."""

import http.server
import ssl
import socket
import socketserver


class DualStackHTTPServer(http.server.HTTPServer):
    """HTTP server that auto-detects TLS or plain HTTP per connection"""

    def __init__(self, server_address, RequestHandlerClass, certfile=None, keyfile=None):
        super().__init__(server_address, RequestHandlerClass)
        self.certfile = certfile
        self.keyfile = keyfile
        if certfile and keyfile:
            self.ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_ctx.load_cert_chain(certfile, keyfile)
        else:
            self.ssl_ctx = None

    def get_request(self):
        client_socket, addr = self.socket.accept()
        if self.ssl_ctx:
            # Peek first bytes to detect TLS ClientHello (starts with 0x16)
            try:
                peek = client_socket.recv(1, socket.MSG_PEEK)
                if peek and peek[0] == 0x16:
                    # TLS handshake
                    client_socket = self.ssl_ctx.wrap_socket(client_socket, server_side=True)
            except Exception as e:
                print("[OUT] TLS peek/wrap error: %s" % e)
        return client_socket, addr


class ThreadedDualStackServer(socketserver.ThreadingMixIn, DualStackHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass
