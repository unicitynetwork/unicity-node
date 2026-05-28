#!/usr/bin/env python3
"""Bug reproducer — RPC server does not support HTTP keep-alive (un-node #5 Priority 3).

The original #5 body listed THREE recommended fixes:
  1. increase listen backlog                                — DONE by PR #11
  2. replace detached threads with thread pool              — STILL OPEN (F2)
  3. support HTTP keep-alive to reduce connection count     — STILL OPEN (this file, F2b)

PR #11 addressed only #1. The server still closes the connection after every
response. Each FGP round opens ~4-6 new Unix-socket connections per FGP node;
with N FGP nodes that's N×6 fresh connect()s per round. With keep-alive, one
connection per node per round would suffice.

This reproducer sends two sequential requests on the SAME socket. If keep-alive
were supported, both would succeed. Currently, the second fails because the
server already closed the connection after the first response.

Exits 0 while the gap is present, 1 when the server starts supporting keep-alive.

Tracking: aggregator-subscription/INVESTIGATIONS.md F2b
"""
import sys
import socket
import json
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def read_http_response(s, timeout=5):
    """Read one HTTP/1.x response (headers + body) off the socket. Returns
    (status_line, headers_dict, body_bytes, server_closed_after) where
    server_closed_after is True if the socket EOF'd after we read the body
    (i.e., the server closed) and False if we appear to still have an open
    connection (recv would block on more data)."""
    s.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            return None, None, None, True
        data += chunk

    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin1", errors="replace")
    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            headers[k.strip().lower().decode()] = v.strip().decode("latin1", errors="replace")

    # Read body if Content-Length present
    body = rest
    cl = int(headers.get("content-length", "0") or "0")
    while len(body) < cl:
        chunk = s.recv(4096)
        if not chunk:
            return status_line, headers, body, True
        body += chunk

    # After reading body, is the server holding the connection open?
    # Do a non-blocking peek with a short timeout: if no more data and no close, it's keep-alive.
    s.settimeout(0.5)
    try:
        extra = s.recv(1, socket.MSG_PEEK)
        # If we got EOF (empty bytes), server closed.
        if extra == b"":
            return status_line, headers, body, True
        # Got more bytes (shouldn't happen for a clean response)
        return status_line, headers, body, False
    except socket.timeout:
        # Nothing more, nothing closed — connection is alive (keep-alive)
        return status_line, headers, body, False


def main():
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_bug_no_keep_alive_'))
    binary = Path(__file__).resolve().parent.parent.parent / "build" / "bin" / "unicityd"
    node = TestNode(0, test_dir / "node0", binary_path=binary,
                    extra_args=[f"--port={pick_free_port()}"], chain="regtest")
    try:
        log("\n" + "=" * 70, BLUE)
        log("BUG REPRODUCER — un-node #5 Priority 3: HTTP keep-alive not supported", BLUE)
        log("=" * 70, BLUE)

        node.start()
        sock_path = str(node.rpc_socket)
        log(f"\n[setup] node up, socket = {sock_path}")

        # Open one socket and send two sequential requests
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(sock_path)

        body = json.dumps({"jsonrpc": "2.0", "method": "getbestblockhash", "params": [], "id": 1})
        req1 = (
            f"POST / HTTP/1.1\r\nHost: localhost\r\n"
            f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n{body}"
        ).encode()

        log("\n[1] send request 1 with `Connection: keep-alive`")
        s.sendall(req1)
        status1, headers1, body1, closed1 = read_http_response(s)
        log(f"  response status:        {status1}")
        log(f"  response Connection:    {headers1.get('connection', '(absent)') if headers1 else '(none)'}")
        log(f"  server closed after:    {closed1}")
        log(f"  response body has result: {b'\"result\"' in (body1 or b'')}")

        # Try sending a second request on the SAME socket
        log("\n[2] send request 2 on the SAME socket")
        body2 = json.dumps({"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 2})
        req2 = (
            f"POST / HTTP/1.1\r\nHost: localhost\r\n"
            f"Content-Length: {len(body2)}\r\nConnection: keep-alive\r\n\r\n{body2}"
        ).encode()
        second_failed = False
        second_err = None
        try:
            s.send(req2)
            status2, headers2, body2_resp, closed2 = read_http_response(s)
            log(f"  response status:        {status2}")
            log(f"  response body has result: {b'\"result\"' in (body2_resp or b'')}")
            if not status2:
                second_failed = True
                second_err = "no response (socket EOF)"
        except (BrokenPipeError, ConnectionResetError, OSError, socket.timeout) as e:
            second_failed = True
            second_err = f"{type(e).__name__}: {e}"
            log(f"  send/recv FAILED: {second_err}")

        s.close()

        log("\n" + "=" * 70, BLUE)
        if (closed1 or "close" in (headers1 or {}).get("connection", "").lower()) and second_failed:
            log("BUG REPRODUCED — server doesn't support HTTP keep-alive.", YELLOW)
            log(f"  • first response had Connection={headers1.get('connection', '(absent)')}", YELLOW)
            log(f"  • server closed socket after first response (closed={closed1})", YELLOW)
            log(f"  • second request on same socket failed: {second_err}", YELLOW)
            log("  → un-node #5 Priority 3 still open. ✅ reproducer working.", YELLOW)
            return 0
        else:
            log("BUG FIXED?  keep-alive appears to work:", GREEN)
            log(f"  • first response Connection: {headers1.get('connection', '(absent)') if headers1 else '(none)'}", GREEN)
            log(f"  • server closed after first: {closed1}", GREEN)
            log(f"  • second request failed: {second_failed} ({second_err})", GREEN)
            log("  → keep-alive support was added. Reproducer OBSOLETE; invert or delete.", GREEN)
            return 1
    finally:
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
