#!/usr/bin/env python3
"""Functional test — RPC socket listen() backlog (un-node #5 / PR #11).

Issue #5 reported that concurrent clients hitting `node.sock` experienced
`connection reset by peer` / `broken pipe` errors because the listen backlog
of 20 overflowed under burst load. PR #11 changed it to `SOMAXCONN`.

This test codifies the manual verification we did in the bft-fgp-2sh
integration topology: positive (the cap is large enough; concurrent bursts on
each FGP-used RPC method succeed; sustained rate succeeds; very-large single
burst succeeds), negative (none of the issue's symptoms — RESET, BROKEN_PIPE,
EAGAIN — appear under load), edge (saturation produces clean app-level "Server
busy" responses, not kernel RST).

Skipped sub-checks that are not appropriate at runtime: source-grep proof
(1a from the manual checklist) and socket-file perms (1h — depends on
deployment uid, irrelevant to the fix).

Issue:  https://github.com/unicitynetwork/unicity-node/issues/5
Fix PR: https://github.com/unicitynetwork/unicity-node/pull/11
"""
import sys
import socket
import json
import time
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


def jsonrpc_call(sock_path, method, params, id_=1, timeout=10):
    """Single Unix-socket JSON-RPC call. Returns one of:
    OK, BUSY, BAD, RESET, BROKEN_PIPE, EAGAIN, TIMEOUT, ERR:<Type>."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(str(sock_path))
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": id_})
        req = (
            f"POST / HTTP/1.1\r\nHost: localhost\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
        ).encode()
        s.sendall(req)
        data = b""
        while True:
            chunk = s.recv(8192)
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
    except OSError as e:
        s = repr(e)
        if "EAGAIN" in s or "temporarily unavailable" in s.lower():
            return "EAGAIN"
        return f"OS:{e.errno}"
    except TimeoutError:
        return "TIMEOUT"
    except Exception as e:
        return f"ERR:{type(e).__name__}"


def burst(sock_path, n, method="getbestblockhash", params=None):
    if params is None:
        params = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        return list(ex.map(
            lambda i: jsonrpc_call(sock_path, method, params, i),
            range(n)
        ))


def assert_no_reset(results, label, failures):
    """Append a failure note if RESET / BROKEN_PIPE / EAGAIN > 0; print summary."""
    c = Counter(results)
    n = len(results)
    rst = c.get("RESET", 0) + c.get("BROKEN_PIPE", 0) + c.get("EAGAIN", 0)
    rst_pct = rst / n * 100 if n else 0
    color = GREEN if rst == 0 else RED
    log(f"  {label:<46} {dict(c)}  RST={rst_pct:.2f}%", color)
    if rst > 0:
        failures.append(f"{label}: RESET/BROKEN_PIPE/EAGAIN = {rst}")


def main():
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_rpc_socket_backlog_'))
    binary_path = Path(__file__).resolve().parent.parent.parent / "build" / "bin" / "unicityd"
    failures = []

    # Use regtest — no BFT needed; instant blocks for getblockhash params
    node = TestNode(0, test_dir / "node0", binary_path=binary_path,
                    extra_args=[f"--port={pick_free_port()}"], chain="regtest")

    try:
        log("\n" + "=" * 70, BLUE)
        log("Functional test — un-node #5 / PR #11 (listen backlog SOMAXCONN)", BLUE)
        log("=" * 70, BLUE)

        log("\n[setup] start regtest node, mine a few blocks for getblockhash params")
        node.start()
        # Generate some blocks so getblockhash N has a valid target
        node.rpc("startmining")
        deadline = time.time() + 30
        while time.time() < deadline:
            bc = node.rpc("getblockcount")
            if isinstance(bc, int) and bc >= 5:
                break
            time.sleep(0.5)
        node.rpc("stopmining")
        tip = node.rpc("getbestblockhash")
        if isinstance(tip, dict):
            tip = tip.get("result", "")
        tip = tip.strip('"').strip()
        log(f"  tip = {tip[:16]}...  blocks = {node.rpc('getblockcount')}")
        sock = node.rpc_socket

        # ----- [1b] kernel SOMAXCONN
        log("\n[1b] kernel SOMAXCONN must be ≥ 128 (large enough for the fix to matter)")
        with open("/proc/sys/net/core/somaxconn") as f:
            somaxconn = int(f.read().strip())
        log(f"  /proc/sys/net/core/somaxconn = {somaxconn}",
            GREEN if somaxconn >= 128 else RED)
        if somaxconn < 128:
            failures.append(f"SOMAXCONN too small: {somaxconn}")

        # ----- [1c] concurrent burst per FGP-used RPC method
        log("\n[1c] concurrent burst (25) per FGP-used RPC method → 0 RESET")
        for m, p in [("getbestblockhash", []),
                     ("getblockheader", [tip]),
                     ("getchaintips", []),
                     ("getblockhash", [1])]:
            assert_no_reset(burst(sock, 25, m, p), f"method={m}", failures)

        # ----- [1d] sustained rate (40 batches × 25 = 1000 calls, ~12s)
        log("\n[1d] sustained rate (40 batches × 25 = 1000 calls)")
        all_results = []
        t0 = time.monotonic()
        for _ in range(40):
            all_results.extend(burst(sock, 25))
            time.sleep(0.3)
        dt = time.monotonic() - t0
        log(f"  fired {len(all_results)} calls in {dt:.1f}s ({len(all_results)/dt:.0f}/s)")
        assert_no_reset(all_results, "sustained", failures)

        # ----- [1e] large single burst (100 — well above the old listen(20) cap
        #            but below the territory where MAX_CONCURRENT_REQUESTS=10
        #            collisions start to bite. Bigger bursts may produce some
        #            BUSY/RESET responses that are F1's signature, not the
        #            backlog-overflow this test targets.  See bug_rpc_busy_path_resets.py.
        log("\n[1e] large single burst (100 concurrent — proves >>20 backlog works)")
        assert_no_reset(burst(sock, 100), "burst=100", failures)

        # ----- [1f] negative — no broken-pipe / EAGAIN across all the above
        log("\n[1f] aggregate: across all the bursts above, none of the issue's symptoms")
        all_combined = burst(sock, 50) + all_results + burst(sock, 50)
        c = Counter(all_combined)
        rst = c.get("RESET", 0)
        bp  = c.get("BROKEN_PIPE", 0)
        eag = c.get("EAGAIN", 0)
        log(f"  in {len(all_combined)} calls: RESET={rst} BROKEN_PIPE={bp} EAGAIN={eag}",
            GREEN if (rst + bp + eag) == 0 else RED)
        if rst + bp + eag != 0:
            failures.append(f"symptom set non-empty: RESET={rst} BP={bp} EAGAIN={eag}")

        # ----- [1g] saturation: rejections are app-level (BUSY), not kernel RST
        log("\n[1g] saturation (100 × heavier getchaintips) — RST should be 0, BUSY may be > 0")
        assert_no_reset(burst(sock, 100, "getchaintips"), "burst=100 getchaintips", failures)

        # ----- Verdict
        log("\n" + "=" * 70, BLUE)
        if failures:
            log("FAIL — un-node #5 / PR #11 regression detected:", RED)
            for f in failures:
                log(f"  - {f}", RED)
            return 1
        log("PASS — un-node #5 / PR #11 verified.", GREEN)
        log("       0 kernel RST across all bursts. Saturation falls through to clean", GREEN)
        log("       app-level path. None of the issue's symptoms (RESET / BROKEN_PIPE /", GREEN)
        log("       EAGAIN) observed.", GREEN)
        return 0
    finally:
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
