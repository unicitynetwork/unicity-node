#!/usr/bin/env python3
"""Design-documentation test — no CLI/RPC list command for mined reward token IDs (by design).

unicity-node issue #1 requirement 11 (verbatim from the requirements comment):
  "Provide a CLI option to just list the token IDs for recent successfully
   mined blocks (along with the corresponding block heights and hashes)."

PR #3 satisfies AC.11 via `<datadir>/reward_tokens.csv` (schema:
Height,BlockHash,TokenID). Per @ahtotruu's clarification (chat, May 28):
"cat csv is also CLI 🙂" — the CSV file IS the CLI option, sufficient until
automation begins. No dedicated `listrewardtokens` / `getrewardtokens` /
equivalent RPC was added, and none is required at this stage.

This file therefore is NOT a bug reproducer — it is a TRIPWIRE / design-
documentation test. It pins the current state ("no list RPC; CSV is the
interface"). It exits 0 while that state holds. It will exit 1 (and need
to be inverted into a positive feature test of the new command's schema)
if/when a future change — most likely as part of issue #13 ("Amend block
reward token handling") which is updating reward-token storage anyway —
introduces a query command. The file lives under the `bug_` prefix
deliberately so test_runner.py does NOT discover it; it's run on demand,
not as default CI.

Tracking: aggregator-subscription/INVESTIGATIONS.md (snapshots req 11)
Related: unicity-node#13 (amend reward-token handling) — when that lands,
revisit whether a query RPC should accompany the new data shape.
"""
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'

# Plausible names an implementer would pick for req 11.
CANDIDATE_COMMANDS = [
    "listrewardtokens",
    "getrewardtokens",
    "listminedtokens",
    "getminedtokens",
    "gettokens",
    "listtokens",
]


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def is_unknown(rv):
    return isinstance(rv, dict) and "unknown command" in str(rv.get("error", "")).lower()


def main():
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_bug_token_list_'))
    binary = Path(__file__).resolve().parent.parent.parent / "build" / "bin" / "unicityd"
    node = TestNode(0, test_dir / "node0", binary_path=binary,
                    extra_args=[f"--port={pick_free_port()}"], chain="regtest")
    try:
        log("\n" + "=" * 70, BLUE)
        log("DESIGN-DOC TRIPWIRE — no list RPC; CSV is the AC.11 interface", BLUE)
        log("=" * 70, BLUE)

        node.start()

        # Mine a few blocks so mined reward tokens actually exist on this node.
        log("\n[1] mine 3 blocks (each generates a reward token)")
        node.generate(3)
        # Confirm a rewardtokenid IS surfaced at template time (tokens exist)...
        tmpl = node.rpc("getblocktemplate")
        has_token_in_template = isinstance(tmpl, dict) and "rewardtokenid" in tmpl
        log(f"  getblocktemplate exposes rewardtokenid: {has_token_in_template}")

        # [2] ...but there's no way to LIST recent mined token IDs + heights + hashes.
        log("\n[2] try plausible list commands")
        results = {}
        for cmd in CANDIDATE_COMMANDS:
            rv = node.rpc(cmd)
            results[cmd] = "Unknown" if is_unknown(rv) else rv
            log(f"  {cmd:20s} → {results[cmd]}")

        all_unknown = all(results[c] == "Unknown" for c in CANDIDATE_COMMANDS)

        log("\n" + "=" * 70, BLUE)
        if all_unknown:
            log("TRIPWIRE HOLDS — no RPC list command, as designed.", GREEN)
            log("  AC.11 is satisfied via reward_tokens.csv per @ahtotruu's", GREEN)
            log("  clarification: \"cat csv is also CLI\" — sufficient until", GREEN)
            log("  automation. If a future change (likely #13 work) adds a", GREEN)
            log("  query RPC, invert this file into a positive feature test", GREEN)
            log("  asserting the new command's schema matches the CSV's.", GREEN)
            return 0
        else:
            implemented = [c for c, v in results.items() if v != "Unknown"]
            log(f"FIXED?  a list command responded: {implemented}", GREEN)
            log("  → A query RPC was added. The design has changed; this", YELLOW)
            log("    tripwire is now obsolete. Invert/replace it with a", YELLOW)
            log("    positive feature test asserting the new command's schema", YELLOW)
            log("    (token-id + height + hash) matches reward_tokens.csv.", YELLOW)
            return 1
    finally:
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
