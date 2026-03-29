"""Proxy handlers: InboundHandler, OutboundHandler, and tunnel_traffic."""

import http.server
import http.client
import urllib.parse
import socket
import select
import ssl
import traceback


def tunnel_traffic(client_sock, remote_sock):
    """Bidirectional tunnel for CONNECT (HTTPS)"""
    sockets = [client_sock, remote_sock]
    try:
        while True:
            readable, _, errors = select.select(sockets, [], sockets, 30)
            if errors:
                break
            for s in readable:
                data = s.recv(8192)
                if not data:
                    return
                if s is client_sock:
                    remote_sock.sendall(data)
                else:
                    client_sock.sendall(data)
    except:
        pass
    finally:
        client_sock.close()
        remote_sock.close()


class InboundHandler(http.server.BaseHTTPRequestHandler):
    burp_host = '127.0.0.1'
    burp_port = 8080
    protocol_version = 'HTTP/1.1'
    plugins = []

    def do_CONNECT(self):
        try:
            remote = socket.create_connection((self.burp_host, self.burp_port), timeout=10)
            connect_req = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (self.path, self.path)
            remote.sendall(connect_req.encode())
            resp = remote.recv(4096)
            self.wfile.write(resp)
            self.wfile.flush()
            print("[IN] CONNECT tunnel: %s" % self.path)
            tunnel_traffic(self.connection, remote)
        except Exception as e:
            print("[IN] CONNECT error: %s" % e)
            try:
                self.send_error(502)
            except:
                pass

    def _proxy_request(self, method):
        print("\n[IN] === REQUEST START ===")
        print("[IN] %s %s" % (method, self.path))
        print("[IN] Headers: %s" % dict(self.headers))

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except:
            content_length = 0
        print("[IN] Content-Length: %d" % content_length)

        try:
            body = self.rfile.read(content_length) if content_length > 0 else b''
        except Exception as e:
            print("[IN] ERROR reading body: %s" % e)
            traceback.print_exc()
            body = b''

        url = self.path
        print("[IN] Body read OK: %d bytes" % len(body))

        converted = False
        extra_headers = {}
        if body:
            for plugin in self.plugins:
                try:
                    if plugin.should_transform_inbound(body, dict(self.headers)):
                        body, extra_headers = plugin.transform_inbound(body, dict(self.headers))
                        converted = True
                        break
                except Exception as e:
                    print("[IN] Plugin %s error: %s" % (plugin.name, e))
                    traceback.print_exc()

        if not converted:
            if body:
                print("[IN] BYPASS (no plugin matched): %d bytes" % len(body))
            else:
                print("[IN] BYPASS (no body)")

        print("[IN] Forwarding to Burp %s:%d ..." % (self.burp_host, self.burp_port))
        try:
            conn = http.client.HTTPConnection(self.burp_host, self.burp_port, timeout=600)

            headers = {}
            for key, val in self.headers.items():
                lk = key.lower()
                if lk not in ('proxy-connection', 'proxy-authorization'):
                    headers[key] = val

            if converted:
                headers['Content-Length'] = str(len(body))

            for hk, hv in extra_headers.items():
                headers[hk] = hv

            conn.request(method, url, body=body, headers=headers)
            print("[IN] Waiting for Burp response...")
            resp = conn.getresponse()
            print("[IN] Burp responded: %d" % resp.status)

            resp_body = resp.read()
            resp_headers_dict = {k: v for k, v in resp.getheaders()}

            # Restore response (JSON -> AMF binary before sending to client)
            resp_extra = {}
            if resp_body:
                for plugin in self.plugins:
                    try:
                        if hasattr(plugin, 'transform_response_encode'):
                            resp_body, resp_extra = plugin.transform_response_encode(resp_body, resp_headers_dict)
                            if resp_extra:
                                break
                    except Exception as e:
                        print("[IN] Plugin %s response error: %s" % (plugin.name, e))
                        traceback.print_exc()

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                lk = key.lower()
                if lk not in ('transfer-encoding', 'content-length', 'connection'):
                    if lk in [k.lower() for k in resp_extra]:
                        continue
                    self.send_header(key, val)
            for hk, hv in resp_extra.items():
                self.send_header(hk, hv)
            self.send_header('Content-Length', str(len(resp_body)))
            self.send_header('Connection', 'close')
            self.end_headers()

            self.wfile.write(resp_body)
            self.wfile.flush()
            conn.close()
            print("[IN] Response sent back to Fiddler: %d bytes" % len(resp_body))
            print("[IN] === REQUEST DONE ===")

        except ConnectionResetError:
            pass
        except ConnectionRefusedError:
            try:
                self.send_error(502)
            except:
                pass
        except OSError:
            pass
        except Exception as e:
            print("[IN] !!! Forward error: %s" % e)
            try:
                self.send_error(502, str(e))
            except:
                pass

    def do_GET(self):
        self._proxy_request('GET')

    def do_POST(self):
        self._proxy_request('POST')

    def do_PUT(self):
        self._proxy_request('PUT')

    def do_HEAD(self):
        self._proxy_request('HEAD')

    def do_OPTIONS(self):
        self._proxy_request('OPTIONS')

    def do_DELETE(self):
        self._proxy_request('DELETE')

    def log_message(self, format, *args):
        pass


class OutboundHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    upstream_host = None  # e.g. '127.0.0.1'
    upstream_port = None  # e.g. 8888
    plugins = []

    def do_CONNECT(self):
        try:
            if self.upstream_host:
                # CONNECT through upstream proxy (Fiddler)
                remote = socket.create_connection((self.upstream_host, self.upstream_port), timeout=10)
                connect_req = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (self.path, self.path)
                remote.sendall(connect_req.encode())
                resp = remote.recv(4096)
                self.wfile.write(resp)
                self.wfile.flush()
                print("[OUT] CONNECT tunnel via upstream: %s" % self.path)
            else:
                host, port = self.path.split(':')
                port = int(port)
                remote = socket.create_connection((host, port), timeout=10)
                self.send_response(200, 'Connection Established')
                self.end_headers()
                print("[OUT] CONNECT tunnel direct: %s" % self.path)
            tunnel_traffic(self.connection, remote)
        except Exception as e:
            print("[OUT] CONNECT error: %s" % e)
            try:
                self.send_error(502)
            except:
                pass

    def _proxy_request(self, method):
        print("\n[OUT] === REQUEST START ===")
        print("[OUT] %s %s" % (method, self.path))
        print("[OUT] Headers: %s" % dict(self.headers))

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except:
            content_length = 0

        try:
            body = self.rfile.read(content_length) if content_length > 0 else b''
        except Exception as e:
            print("[OUT] ERROR reading body: %s" % e)
            traceback.print_exc()
            body = b''

        url = self.path
        parsed = urllib.parse.urlparse(url)
        # Host header port fallback (Burp may strip port from URL)
        host_header = self.headers.get('Host', '')
        if ':' in host_header:
            hh_host, hh_port = host_header.rsplit(':', 1)
            try:
                hh_port = int(hh_port)
            except:
                hh_host = host_header
                hh_port = None
        else:
            hh_host = host_header
            hh_port = None

        # 들어온 연결이 TLS면 원래 HTTPS 트래픽 → 기본 포트 443
        inbound_is_tls = hasattr(self.connection, 'getpeercert')
        default_port = 443 if (parsed.scheme == 'https' or inbound_is_tls) else 80

        target_host = parsed.hostname or hh_host
        target_port = parsed.port or hh_port or default_port
        path = parsed.path
        if parsed.query:
            path += '?' + parsed.query

        print("[OUT] Target: %s:%d%s" % (target_host, target_port, path))
        print("[OUT] Body: %d bytes" % len(body))

        converted = False
        extra_headers = {}
        if body:
            for plugin in self.plugins:
                try:
                    if plugin.should_transform_outbound(body, dict(self.headers)):
                        body, extra_headers = plugin.transform_outbound(body, dict(self.headers))
                        converted = True
                        break
                except Exception as e:
                    print("[OUT] Plugin %s error: %s" % (plugin.name, e))
                    traceback.print_exc()

        if not converted:
            if body:
                print("[OUT] BYPASS (no plugin matched): %d bytes" % len(body))
            else:
                print("[OUT] BYPASS (no body)")

        use_upstream = self.upstream_host is not None

        if use_upstream:
            print("[OUT] Connecting via upstream %s:%d to %s:%d ..." % (self.upstream_host, self.upstream_port, target_host, target_port))
        else:
            print("[OUT] Connecting to target %s:%d ..." % (target_host, target_port))
        try:
            if use_upstream:
                # Send through upstream proxy (Fiddler) - use full URL
                conn = http.client.HTTPConnection(self.upstream_host, self.upstream_port, timeout=600)
                request_path = url  # full URL for proxy request
            else:
                use_tls = parsed.scheme == 'https' or inbound_is_tls
                if use_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(target_host, target_port, timeout=600, context=ctx)
                else:
                    conn = http.client.HTTPConnection(target_host, target_port, timeout=600)
                request_path = path

            headers = {}
            for key, val in self.headers.items():
                lk = key.lower()
                if lk not in ('proxy-connection', 'proxy-authorization',
                              'x-ssv-converted', 'x-original-target'):
                    headers[key] = val

            if converted:
                headers['Content-Length'] = str(len(body))

            for hk, hv in extra_headers.items():
                headers[hk] = hv

            conn.request(method, request_path, body=body, headers=headers)
            print("[OUT] Waiting for target response...")
            resp = conn.getresponse()
            print("[OUT] Target responded: %d" % resp.status)

            resp_body = resp.read()
            resp_headers_dict = {k: v for k, v in resp.getheaders()}

            # Transform response (AMF binary -> JSON for Burp viewing)
            resp_extra = {}
            if resp_body:
                for plugin in self.plugins:
                    try:
                        if plugin.should_transform_response(resp_body, resp_headers_dict):
                            resp_body, resp_extra = plugin.transform_response_decode(resp_body, resp_headers_dict)
                            break
                    except Exception as e:
                        print("[OUT] Plugin %s response error: %s" % (plugin.name, e))
                        traceback.print_exc()

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                lk = key.lower()
                if lk not in ('transfer-encoding', 'content-length', 'connection'):
                    if lk in [k.lower() for k in resp_extra]:
                        continue
                    self.send_header(key, val)
            for hk, hv in resp_extra.items():
                self.send_header(hk, hv)
            self.send_header('Content-Length', str(len(resp_body)))
            self.send_header('Connection', 'close')
            self.end_headers()

            self.wfile.write(resp_body)
            self.wfile.flush()
            conn.close()
            print("[OUT] Response sent back to Burp: %d bytes" % len(resp_body))
            print("[OUT] === REQUEST DONE ===")

        except ConnectionResetError:
            pass
        except ConnectionRefusedError:
            try:
                self.send_error(502)
            except:
                pass
        except OSError:
            pass
        except Exception as e:
            print("[OUT] !!! Forward error: %s" % e)
            try:
                self.send_error(502, str(e))
            except:
                pass

    def do_GET(self):
        self._proxy_request('GET')

    def do_POST(self):
        self._proxy_request('POST')

    def do_PUT(self):
        self._proxy_request('PUT')

    def do_HEAD(self):
        self._proxy_request('HEAD')

    def do_OPTIONS(self):
        self._proxy_request('OPTIONS')

    def do_DELETE(self):
        self._proxy_request('DELETE')

    def log_message(self, format, *args):
        pass
