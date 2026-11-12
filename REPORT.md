VERDICT: YES — the tool builds and appends canonical, chained Ed25519-signed MOLT events.
Tests: 14 passed, 0 failed (`npm test`, Node.js v22.23.4).

## Files

- `molt-event.mjs` — standalone append CLI
- `molt-canonical.mjs` — supplied canonicalizer, copied unchanged (SHA-256: `5e4c0503fbefa64503616551bc56e743e4681e40a009590f9eaf315a9c8dcff3`)
- `tests/event.test.mjs` — built-in Node test suite with fresh temporary Ed25519 identities
- `package.json` — `npm test` runs `node --test`
- `README.md` — usage, identities, event format, formulas, and pairing notes
- `REPORT.md` — this report

## Test results

Command: `npm test` (runs `node --test`)

- Tests: 14
- Passed: 14
- Failed: 0
- Skipped/cancelled: 0

The suite checks first and subsequent appends, canonical JSON, sequence and chain order, independently recomputed event hashes, direct Ed25519 verification, stdin and all required JSON payload types, malformed ledger and payload handling, mismatched identity rejection, creation of a missing ledger, both supported identity layouts, CLI errors, and that the private seed is absent from output. JavaScript syntax checks passed, and the bundled canonicalizer was verified byte-for-byte against the supplied file.

## Event format and formulas implemented

The event has exactly `seq`, `ts`, `type`, `actor`, `payload`, `prev_hash`, `pub`, `sig`, and `hash`. `seq` is the count of non-empty valid ledger lines; the first `prev_hash` is 64 zeroes, and later events use the last event's 64-character lowercase hexadecimal `hash`.

The body is the first seven fields, excluding `sig` and `hash`. It is canonicalized with the imported `canonicalizeJsonText` function. The event hash is lowercase hexadecimal SHA-256 of the UTF-8 bytes of `prev_hash` followed directly by the canonical body. The Ed25519 signature is lowercase hexadecimal signing of the canonical body's UTF-8 bytes. The complete event is canonicalized and appended as one newline-terminated JSONL record.

Identity handling accepts the manifest-signer and `molt.ed25519-identity.v1` layouts used by `molt-sign`, validates the seed-to-public-key match, and checks the v1 key ID. The tool checks ledger lines are valid JSON objects with a valid-format hash field, but it does not verify prior signatures or the full ledger chain; use the separate L1 verifier for that.

## Open items

- Node.js 24 could not be tested because only Node.js 22.23.4 is installed in this environment. The implementation uses Node built-ins supported by the stated Node 22/24 versions; verification on Node 24 remains open.
- Concurrent writers are not serialized or locked. If multiple processes may append to the same ledger simultaneously, a single-writer policy or locking would need to be specified.
- No product decisions are pending.

## What was NOT done

- No existing MOLT file, ledger, key, or configuration was changed; no real ledger event was appended.
- No real key was generated or used. Test-only keys were generated temporarily by the test suite and removed.
- No network access, repository push, deployment, or full-ledger verification was performed.
