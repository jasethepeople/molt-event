# MOLT event writer — Camp 1 compatibility

The writer now emits MOLT-CORE Camp 1 events: the hash covers `prev_hash` text plus the canonical five-field body (`seq`, `ts`, `type`, `payload`, `actor`), and Ed25519 signs the 32 raw hash bytes.

## Verification

- `npm test`: 16 passed, 0 failed.
- Existing ledgers are fully checked for canonical form, exact Camp 1 fields, sequence, hash chain, signatures, and a single package public key before appending.
- Earlier seven-field ledgers and attempts to append with a different key are rejected without modifying the ledger.
- End-to-end test path passed: writer → `molt-verify-ledger` → `molt-verify` L1 package verifier → `molt-anchor`.

Cross-implementation interoperability is confirmed for ASCII event content. MOLT-CORE leaves non-ASCII canonicalization open; this change does not adopt the separate Foundry-compatibility canonicalizer from the uploaded archive.

No real identity, key, or ledger was used; tests create temporary keys and ledgers.
