#!/usr/bin/env python3
"""Independent checker for forward-ledger anchors. Standard library only.

    python3 verify_anchors.py anchors.jsonl
        Checks the whole anchor chain: every hash recomputes, every anchor
        links to the one before it, dates increase, windows are contiguous.

    python3 verify_anchors.py anchors.jsonl --record HASH --date DATE --index I --path H1,H2,...
        Also checks that a record hash is included in the anchor for DATE,
        using the inclusion proof the site gives the record's owner.

Exit status 0 means everything checked out. Timestamps are checked
separately with the OpenTimestamps client: `ots verify stamps/DATE.anchor.ots`.

Formats (docs/DESIGN.md in the main repository):
    anchor_hash = SHA256("fl1-anchor\\n" + prev_anchor + "\\n" + date + "\\n"
                         + record_count + "\\n" + merkle_root + "\\n")
    Merkle tree: RFC 6962. Leaf = SHA256(0x00 || record hash bytes),
    node = SHA256(0x01 || left || right), empty tree = SHA256("").
"""

import argparse
import hashlib
import json
import re
import sys

HEX64 = re.compile(r"^[0-9a-f]{64}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
ZERO = "0" * 64
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def anchor_hash(a):
    text = f"fl1-anchor\n{a['prev_anchor']}\n{a['anchor_date']}\n{a['record_count']}\n{a['merkle_root']}\n"
    return hashlib.sha256(text.encode()).hexdigest()


def check_chain(anchors):
    problems = []
    prev, last = ZERO, None
    for a in anchors:
        at = f"anchor {a.get('anchor_date')}: "
        try:
            ok_fields = (DATE.match(a["anchor_date"]) and TS.match(a["window_end"])
                         and (a["window_start"] is None or TS.match(a["window_start"]))
                         and isinstance(a["record_count"], int) and a["record_count"] >= 0
                         and all(HEX64.match(a[k]) for k in ("merkle_root", "prev_anchor", "anchor_hash")))
        except (KeyError, TypeError):
            ok_fields = False
        if not ok_fields:
            problems.append(at + "missing or malformed fields")
            break
        if a["window_start"] is not None and not a["window_start"] < a["window_end"]:
            problems.append(at + "window is empty or reversed")
        if a["prev_anchor"] != prev:
            problems.append(at + "does not link to the previous anchor")
        if anchor_hash(a) != a["anchor_hash"]:
            problems.append(at + "anchor hash does not match its fields")
        if a["record_count"] == 0 and a["merkle_root"] != EMPTY_ROOT:
            problems.append(at + "empty window must have the empty root")
        if last is None:
            if a["window_start"] is not None:
                problems.append(at + "first anchor must have no window start")
        else:
            if not last["anchor_date"] < a["anchor_date"]:
                problems.append(at + "dates must strictly increase")
            if a["window_start"] != last["window_end"]:
                problems.append(at + "window does not start where the previous ended")
        prev, last = a["anchor_hash"], a
    return problems


def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion(record_hash_hex, index, size, path_hex, root_hex):
    """RFC 9162 section 2.1.3.2."""
    if index >= size:
        return False
    fn, sn = index, size - 1
    r = hashlib.sha256(b"\x00" + bytes.fromhex(record_hash_hex)).digest()
    for p in (bytes.fromhex(h) for h in path_hex):
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == root_hex


def main(argv):
    ap = argparse.ArgumentParser(description="Check forward-ledger anchors.")
    ap.add_argument("anchors")
    ap.add_argument("--record", help="record hash to check for inclusion")
    ap.add_argument("--date", help="anchor date the record should be in")
    ap.add_argument("--index", type=int, help="leaf index from the inclusion proof")
    ap.add_argument("--path", default="", help="comma-separated proof hashes")
    args = ap.parse_args(argv)

    with open(args.anchors, encoding="utf-8") as f:
        anchors = [json.loads(line) for line in f if line.strip()]
    problems = check_chain(anchors)
    for p in problems:
        print("FAIL", p)
    if problems:
        return 1
    print(f"OK chain: {len(anchors)} anchors, head {anchors[-1]['anchor_hash'] if anchors else '(none)'}")

    if args.record:
        if args.date is None or args.index is None:
            print("FAIL --record needs --date and --index")
            return 2
        path = [h for h in args.path.split(",") if h]
        if not HEX64.match(args.record) or not all(HEX64.match(h) for h in path):
            print("FAIL hashes must be 64 lowercase hex characters")
            return 2
        match = [a for a in anchors if a["anchor_date"] == args.date]
        if not match:
            print(f"FAIL no anchor for {args.date}")
            return 1
        a = match[0]
        if not verify_inclusion(args.record, args.index, a["record_count"], path, a["merkle_root"]):
            print(f"FAIL the proof does not show record {args.record} in the {args.date} anchor")
            return 1
        print(f"OK record {args.record} is in the {args.date} anchor ({a['record_count']} records)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
