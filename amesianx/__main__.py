#!/usr/bin/env python3
"""
Amesianx Proxy — General-purpose proxy tool (red team edition)

Flow:
  Browser -> Fiddler(8888) -> Proxy-IN(8089) [plugin transform] -> Burp(8080) [edit]
  Burp -> Proxy-OUT(8099) [plugin reverse-transform] -> Target Server

Usage:
  python -m amesianx --listen-in 8089 --listen-out 8099 --burp 8080
  python -m amesianx --no-nexacro          # pure proxy, no plugins
  python -m amesianx --gen-cert             # generate fresh cert via openssl
"""

import argparse
import http.server
import socketserver
import threading

from .core.proxy import InboundHandler, OutboundHandler
from .core.server import DualStackHTTPServer, ThreadedDualStackServer
from .core.certs import write_embedded_cert, generate_cert_openssl
from .plugins import discover_plugins


def main():
    parser = argparse.ArgumentParser(description='Amesianx Proxy — General-purpose proxy tool (red team edition)')
    parser.add_argument('--listen-in', type=int, default=8089,
                        help='Inbound port (Fiddler -> Proxy), default: 8089')
    parser.add_argument('--listen-out', type=int, default=8099,
                        help='Outbound port (Burp -> Proxy), default: 8099')
    parser.add_argument('--burp', type=int, default=8080,
                        help='Burp proxy port, default: 8080')
    parser.add_argument('--upstream', type=int, default=None,
                        help='Upstream proxy port for outbound (e.g. Fiddler 8888)')
    parser.add_argument('--no-nexacro', action='store_true',
                        help='Disable NexacroSSV plugin')
    parser.add_argument('--no-amf', action='store_true',
                        help='Disable AMF plugin')
    parser.add_argument('--raw-response', action='store_true',
                        help='Do not decode AMF responses (show raw binary in Burp)')
    parser.add_argument('--gen-cert', action='store_true',
                        help='Generate fresh self-signed cert via openssl CLI instead of using embedded cert')
    args = parser.parse_args()

    # Build plugin list via auto-discovery, with per-plugin disable flags
    disabled = set()
    if args.no_nexacro:
        disabled.add('NexacroSSV')
    if args.no_amf:
        disabled.add('AMF')

    active_plugins = []
    for plugin_cls in discover_plugins():
        if plugin_cls.name not in disabled:
            if plugin_cls.name in ('AMF', 'NexacroSSV'):
                active_plugins.append(plugin_cls(decode_response=not args.raw_response))
            else:
                active_plugins.append(plugin_cls())

    plugin_names = [p.name for p in active_plugins] if active_plugins else ["(none)"]

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        def handle_error(self, request, client_address):
            pass

    InboundHandler.burp_host = '127.0.0.1'
    InboundHandler.burp_port = args.burp
    InboundHandler.plugins = active_plugins

    OutboundHandler.plugins = active_plugins
    if args.upstream:
        OutboundHandler.upstream_host = '127.0.0.1'
        OutboundHandler.upstream_port = args.upstream

    # Certificate setup
    if args.gen_cert:
        print("[*] Generating fresh self-signed certificate via openssl CLI...")
        cert_path, key_path = generate_cert_openssl()
    else:
        print("[*] Using embedded self-signed certificate for Proxy-OUT TLS...")
        cert_path, key_path = write_embedded_cert()
    print("[*] Cert: %s" % cert_path)

    in_server = ThreadedHTTPServer(('127.0.0.1', args.listen_in), InboundHandler)
    out_server = ThreadedDualStackServer(('127.0.0.1', args.listen_out), OutboundHandler,
                                         certfile=cert_path, keyfile=key_path)

    upstream_info = "127.0.0.1:%d (Fiddler)" % args.upstream if args.upstream else "DIRECT"

    banner = """
============================================================
  Amesianx Proxy — General-purpose proxy (red team edition)
============================================================

  Active Plugins: %s

  [Inbound]  127.0.0.1:%d  (Fiddler -> here, plugin transform)
  [Burp]     127.0.0.1:%d       (editing)
  [Outbound] 127.0.0.1:%d  (Burp -> here, plugin reverse -> %s) [HTTP+TLS]

  Fiddler Setup:
    Tools > Options > Gateway > Manual Proxy: 127.0.0.1:%d

  Burp Setup:
    1. Proxy Listener: 127.0.0.1:%d
    2. Settings > Network > Connections > Upstream Proxy:
       Destination: *  Proxy: 127.0.0.1  Port: %d

  * Plugin-matched requests -> transformed for editing in Burp
  * Non-matched requests -> bypassed as-is
  * Responses -> always bypassed as-is

  Press Ctrl+C to stop.
============================================================
""" % (', '.join(plugin_names),
       args.listen_in, args.burp, args.listen_out, upstream_info,
       args.listen_in, args.burp, args.listen_out)

    print(banner)

    in_thread = threading.Thread(target=in_server.serve_forever, daemon=True)
    out_thread = threading.Thread(target=out_server.serve_forever, daemon=True)

    in_thread.start()
    out_thread.start()

    try:
        while True:
            in_thread.join(timeout=1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        in_server.shutdown()
        out_server.shutdown()


if __name__ == '__main__':
    main()
