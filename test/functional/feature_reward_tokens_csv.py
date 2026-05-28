#!/usr/bin/env python3
"""Feature test — reward_tokens.csv is the AC.11 interface (per @ahtotruu).

unicity-node issue #1 requirement 11 asks for "a CLI option to just list the
token IDs for recent successfully mined blocks (along with the corresponding
block heights and hashes)." PR #3 satisfies this via `<datadir>/reward_tokens.csv`
with the exact schema AC.11 specifies:

    Height,BlockHash,TokenID

Per @ahtotruu's clarification (chat, May 28): "cat csv is also CLI 🙂" — the
CSV file IS the CLI option, sufficient until automation begins. No dedicated
RPC is needed at this stage (see bug_reward_token_list_missing.py for the
companion design-doc tripwire).

This test mines N blocks, then asserts the CSV exists, is well-formed, and
contains one row per mined block with valid hex values + the expected column
shape. It pins the AC.11 interface so any regression in CSV format/location
is caught here.

⚠ Heads-up for whoever picks up unicity-node#13 ("Amend block reward token
handling"): that issue will change WHAT gets stored per-block per the
yellowpaper updates (unicity-yellowpaper-tex#4 and #5). When #13 lands, the
CSV schema or contents may change, and this test will need updating
accordingly — re-pin to the new schema, and update bug_reward_token_list_missing.py
in lockstep.

Tracking: aggregator-subscription/INVESTIGATIONS.md (snapshots req 11)
Related: unicity-node#13.
"""
import csv
import sys
import tempfile
import shutil
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def main():
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_feature_reward_csv_'))
    binary = Path(__file__).resolve().parent.parent.parent / "build" / "bin" / "unicityd"
    node = TestNode(0, test_dir / "node0", binary_path=binary,
                    extra_args=[f"--port={pick_free_port()}"], chain="regtest")
    rc = 1
    try:
        log("\n" + "=" * 70, BLUE)
        log("FEATURE — reward_tokens.csv exposes (Height, BlockHash, TokenID)", BLUE)
        log("=" * 70, BLUE)

        node.start()

        N = 3
        log(f"\n[1] mine {N} blocks (each generates a reward token)")
        node.generate(N)

        csv_path = node.datadir / "reward_tokens.csv"
        log(f"\n[2] check {csv_path}")
        if not csv_path.exists():
            log(f"  FAIL — file does not exist", RED)
            return 1

        with open(csv_path, "r", newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Header line
        header = rows[0]
        log(f"  header: {header}")
        if header != ["Height", "BlockHash", "TokenID"]:
            log(f"  FAIL — header must be exactly ['Height','BlockHash','TokenID']", RED)
            return 1

        # One data row per mined block
        data = rows[1:]
        log(f"  data rows: {len(data)}")
        if len(data) != N:
            log(f"  FAIL — expected {N} rows, got {len(data)}", RED)
            return 1

        # Each row: Height is int, BlockHash + TokenID are 64-char hex; Height increments
        seen_token_ids = set()
        seen_block_hashes = set()
        prev_height = 0
        for i, row in enumerate(data, start=1):
            if len(row) != 3:
                log(f"  FAIL — row {i} has {len(row)} fields, expected 3: {row}", RED)
                return 1
            h, bh, tid = row
            try:
                h_int = int(h)
            except ValueError:
                log(f"  FAIL — row {i} Height not int: {h!r}", RED)
                return 1
            if h_int <= prev_height:
                log(f"  FAIL — Height not strictly increasing at row {i}: {h_int} <= {prev_height}", RED)
                return 1
            prev_height = h_int
            if not HEX64.match(bh):
                log(f"  FAIL — row {i} BlockHash not 64 hex chars: {bh!r}", RED)
                return 1
            if not HEX64.match(tid):
                log(f"  FAIL — row {i} TokenID not 64 hex chars: {tid!r}", RED)
                return 1
            if tid in seen_token_ids:
                log(f"  FAIL — duplicate TokenID at row {i}: {tid} (req 8 violation)", RED)
                return 1
            if bh in seen_block_hashes:
                log(f"  FAIL — duplicate BlockHash at row {i}: {bh}", RED)
                return 1
            seen_token_ids.add(tid)
            seen_block_hashes.add(bh)
            log(f"  row {i}: H={h_int} BH={bh[:16]}... TID={tid[:16]}...")

        log("\n" + "=" * 70, BLUE)
        log("PASS — reward_tokens.csv has the req-11 schema and content.", GREEN)
        log(f"       Header + {N} rows; all hex valid; heights strictly increasing;", GREEN)
        log(f"       token IDs distinct (req 8 cross-check).", GREEN)
        rc = 0
        return rc
    finally:
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
