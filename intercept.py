"""
    ODNS InterceptResolver - decypher ODNS requests and proxy to upstream
    server
"""
from __future__ import print_function

import socket

from dnslib import DNSRecord, RCODE
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger
from odns import ODNSCypher


class ODNSInterceptResolver(BaseResolver):

    """
        ODNS Intercepting resolver

        Proxy requests to upstream server and decyphering ODNS requests
    """

    def __init__(self, address, port, skip, key_path, timeout=0):
        """
            address/port    - upstream server
            skip            - list of wildcard labels to skip
            timeout         - timeout for upstream server
            key_path        - path to server secret key
        """
        self.address = address
        self.port = port
        self.skip = skip
        self.timeout = timeout

        self.server_sk = None
        with open(key_path, 'rb') as f:
            self.server_sk = f.read()

        self.crypto = ODNSCypher(server_sk=self.server_sk)

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        print("QNAME : ", qname)

        # Test if we match skip
        if not any([qname.matchGlob(s) for s in self.skip]):
            # Decypher the query and replace with clear qname
            crypted = qname.stripSuffix("odns")
            crypted = str(crypted)[:-1]  # Remove the trailing.
            crypted = bytes.fromhex(crypted)  # Convert to bytes

            clear_request, aes_key = self.crypto.decrypt_query(crypted)

            request.q.qname = clear_request
            # Forward it to the upstream server
            try:
                if handler.protocol == 'udp':
                    proxy_r = request.send(self.address, self.port,
                                           timeout=self.timeout)
                else:
                    proxy_r = request.send(self.address, self.port,
                                           tcp=True, timeout=self.timeout)
                # Cypher back the reply
                reply = DNSRecord.parse(proxy_r)
                reply.q.qname = self.crypto.encrypt_answer(
                    reply.q.qname.encode(), aes_key)
            except socket.timeout:
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

        # Else, just proxy
        if not reply.rr:
            try:
                if handler.protocol == 'udp':
                    proxy_r = request.send(self.address, self.port,
                                           timeout=self.timeout)
                else:
                    proxy_r = request.send(self.address, self.port,
                                           tcp=True, timeout=self.timeout)
                reply = DNSRecord.parse(proxy_r)
            except socket.timeout:
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

        return reply


if __name__ == '__main__':

    import argparse
    import time

    p = argparse.ArgumentParser(description="ODNS Proxy")
    p.add_argument("--port", "-p", type=int, default=5553,
                   metavar="<port>",
                   help="Local proxy port (default:5553)")
    p.add_argument("--address", "-a", default="",
                   metavar="<address>",
                   help="Local proxy listen address (default:all)")
    p.add_argument("--upstream", "-u", default="8.8.8.8:53",
                   metavar="<dns server:port>",
                   help="Upstream DNS server:port (default:8.8.8.8:53)")
    p.add_argument("--skip", "-s", action="append",
                   metavar="<label>",
                   help="Don't intercept matching label (glob)")
    p.add_argument("--timeout", "-o", type=float, default=5,
                   metavar="<timeout>",
                   help="Upstream timeout (default: 5s)")
    p.add_argument("--key", "-k", default="./key.pem",
                   metavar="<key_path>",
                   help="Path to the server secret key")
    p.add_argument("--log", default="request,reply,truncated,error",
                   help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix", action='store_true', default=False,
                   help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    args.dns, _, args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    resolver = ODNSInterceptResolver(args.dns,
                                     args.dns_port,
                                     args.skip or [],
                                     args.key,
                                     args.timeout)
    logger = DNSLogger(args.log, args.log_prefix)

    print("Starting ODNS Poxy ({}:{} -> {}:{}) [{}]".format(
        args.address or "*", args.port,
        args.dns, args.dns_port,
        "UDP/TCP" if args.tcp else "UDP"))

    if resolver.skip:
        print("    Skipping:", ", ".join(resolver.skip))
    print()

    DNSHandler.log = {
        'log_request',      # DNS Request
        'log_reply',        # DNS Response
        'log_truncated',    # Truncated
        'log_error',        # Decoding error
    }

    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)
