# forward-ledger anchors

This repository is the public record of forward-ledger's daily anchors. It
is written by an automated job and contains no positions, prices or
personal data: only hashes, dates and record counts.

## What an anchor is

Every submission to forward-ledger is a record with a SHA-256 hash. Once a
day, after the 09:00 New York cutoff, all records received since the
previous cutoff are combined into one Merkle tree (RFC 6962), and its root
is written here together with the record count. Each anchor also commits to
the previous anchor's hash, so the anchors form a chain.

Once an anchor is here, changing, removing or backdating any record it
covers would change that anchor's root, and with it every later anchor.

## Files

| File | Contents |
|---|---|
| `anchors.jsonl` | One anchor per line, oldest first. |
| `stamps/DATE.anchor` | The anchor line for DATE, exactly as published. |
| `stamps/DATE.anchor.ots` | An OpenTimestamps proof that the file above existed at that time, ultimately recorded in the Bitcoin blockchain. Proofs are upgraded as confirmations arrive. |
| `verify_anchors.py` | A checker that needs only Python 3. |

## Checking it yourself

Check the whole chain:

```sh
python3 verify_anchors.py anchors.jsonl
```

Check one timestamp (needs the OpenTimestamps client, `pip install opentimestamps-client`):

```sh
ots verify stamps/2027-01-04.anchor.ots
```

Check that one of your own records is included, using the inclusion proof
shown for that record on the site:

```sh
python3 verify_anchors.py anchors.jsonl --record <record hash> --date <anchor date> --index <i> --path <h1,h2,...>
```

You also do not need to trust this repository's history. Keep your own copy
of `anchors.jsonl` (or of any anchor hash): any later change to a published
anchor breaks the chain from that point on.

## What this does not show

The anchors show that records were not changed after anchoring. They do not
say anything about how well a strategy did, and the scores on the site are
from a simulated forward test, not real trading. Not investment advice.
