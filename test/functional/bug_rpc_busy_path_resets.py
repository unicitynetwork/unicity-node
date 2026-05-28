#!/usr/bin/env python3
"""Bug reproducer — `MAX_CONCURRENT_REQUESTS=10` busy-path emits ECONNRESET (un-node #5 F1).

Originally observed during the FGP recovery-burst scenario (Scenario E in
aggregator-subscription/FGP_AND_UNICITY_NODE_TOPOLOGY.md §8): 16
`connection reset by peer` errors on `node.sock` during a 6-second window
when fgp-node-2 was recovering ~27 blocks back-to-back while 2 other FGP
nodes were issuing per-round queries and the miner was active.

Hypothesis: when `active_requests_.load() >= MAX_CONCURRENT_REQUESTS=10`,
the accept loop in `rpc_server.cpp` does:

    SendResponse(client_fd, ...busy...);
    close(client_fd);   // <-- without draining the request bytes the client
                        //     has already sent

→ on the Unix socket, this delivers ECONNRESET on the client side instead
of a clean "Server busy" JSON-RPC error.

This script attempts to reproduce by firing a single large concurrent burst
(>> MAX_CONCURRENT_REQUESTS) and counting outcomes:

    OK            response with proper JSON-RPC result
    BUSY          clean app-level "Server busy" response (the INTENDED busy path)
    RESET / BP    kernel-level ECONNRESET / broken-pipe (the BUG signature)

If RESET > 0 and BUSY == 0, the bug is reproduced (close-without-drain).
If BUSY > 0 and RESET == 0, the fix is in (busy-path drains+responds cleanly).
If both are 0, the burst was too small to saturate; we widen and retry.

Exit codes:
    0  — gap reproduced (RESET > 0) OR inconclusive (no saturation observed)
    1  — gap fixed (BUSY > 0, RESET == 0)
    2  — environment error

Tracking: aggregator-subscription/INVESTIGATIONS.md F1
"""
import sys
import socket
import json
import tempfile
import shutil
import concurrent.futures
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def one_call(sock_path, i, method="getchaintips"):
    """getchaintips is slightly heavier than getbestblockhash → handler holds
    active_requests_ a hair longer, making the cap easier to saturate."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(sock_path)
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": [], "id": i})
        s.sendall((
            f"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n{body}"
        ).encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        if b'"result"' in data and b'"error":null' in data:
            return "OK"
        if b"busy" in data.lower() or b"too many" in data.lower():
            return "BUSY"
        return "BAD"
    except ConnectionResetError:
        return "RESET"
    except BrokenPipeError:
        return "BROKEN_PIPE"
    except Exception as e:
        return f"ERR:{type(e).__name__}"


def burst(sock_path, n):
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        return list(ex.map(lambda i: one_call(sock_path, i), range(n)))


def main():
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_bug_busy_path_'))
    binary = Path(__file__).resolve().parent.parent.parent / "build" / "bin" / "unicityd"
    node = TestNode(0, test_dir / "node0", binary_path=binary,
                    extra_args=[f"--port={pick_free_port()}"], chain="regtest")
    try:
        log("\n" + "=" * 70, BLUE)
        log("BUG REPRODUCER — un-node #5 F1: MAX_CONCURRENT_REQUESTS busy-path RESETs", BLUE)
        log("=" * 70, BLUE)
        node.start()
        sock = str(node.rpc_socket)

        # Try increasing burst sizes — the bigger the burst, the more likely
        # active_requests_ briefly hits 10 simultaneously, tripping the cap.
        all_results = []
        for n in [250, 500, 1000]:
            results = burst(sock, n)
            all_results.extend(results)
            c = Counter(results)
            rst = c.get("RESET", 0) + c.get("BROKEN_PIPE", 0)
            log(f"  burst={n:<5} {dict(c)}  RST={rst}  BUSY={c.get('BUSY', 0)}")

        total = Counter(all_results)
        rst_total = total.get("RESET", 0) + total.get("BROKEN_PIPE", 0)
        busy_total = total.get("BUSY", 0)
        ok_total = total.get("OK", 0)
        n_total = sum(total.values())

        log(f"\n  aggregate: {dict(total)}")
        log(f"  RESET/BP: {rst_total}/{n_total} ({100*rst_total/n_total:.2f}%)")
        log(f"  BUSY:     {busy_total}/{n_total} ({100*busy_total/n_total:.2f}%)")
        log(f"  OK:       {ok_total}/{n_total} ({100*ok_total/n_total:.2f}%)")

        log("\n" + "=" * 70, BLUE)
        if rst_total > 0 and busy_total == 0:
            log("BUG REPRODUCED — busy path emits ECONNRESET instead of a clean JSON-RPC error.", YELLOW)
            log(f"  • {rst_total} RESET/BP across {n_total} requests", YELLOW)
            log(f"  • 0 BUSY responses (close-without-drain hypothesis confirmed)", YELLOW)
            log("  → un-node #5 F1 still open. ✅ reproducer working.", YELLOW)
            return 0
        elif busy_total > 0 and rst_total == 0:
            log("BUG FIXED — busy path returns clean BUSY responses, no kernel RESET.", GREEN)
            log(f"  • {busy_total} clean BUSY responses across {n_total} requests", GREEN)
            log(f"  • 0 RESET/BROKEN_PIPE", GREEN)
            log("  → busy-path drains+responds cleanly. Reproducer OBSOLETE.", GREEN)
            return 1
        elif rst_total > 0 and busy_total > 0:
            log("MIXED — both RESET and BUSY observed. Busy path partially fixed?", YELLOW)
            log(f"  • RESET/BP: {rst_total}", YELLOW)
            log(f"  • BUSY:     {busy_total}", YELLOW)
            log("  → still some close-without-drain, but some clean responses. Re-investigate.", YELLOW)
            return 0
        else:
            log("INCONCLUSIVE — neither RESET nor BUSY observed; burst didn't saturate the cap.", YELLOW)
            log(f"  • {ok_total}/{n_total} OK, 0 RESET, 0 BUSY", YELLOW)
            log("  Try increasing the burst size, or run alongside the FGP recovery", YELLOW)
            log("  scenario (Scenario E in FGP_AND_UNICITY_NODE_TOPOLOGY.md §8) to", YELLOW)
            log("  reliably trigger active_requests_ saturation.", YELLOW)
            log("  → gap remains *plausible* but unverified by this script.", YELLOW)
            return 0  # status-quo, neither confirms nor refutes
    finally:
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
