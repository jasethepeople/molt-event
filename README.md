# molt-event

A standalone Node.js command-line tool that builds and appends one Ed25519-signed, SHA-256 hash-chained event to a JSON Lines ledger. It uses only Node.js built-ins plus the supplied `molt-canonical.mjs`; there are no external dependencies, network calls, key-generation commands, or build steps.

## Requirements and tests

Use Node.js 22 or 24. No install step is required. Run the included tests with:

```sh
npm test
```

The test suite uses Node's built-in test runner. It generates fresh, temporary Ed25519 keypairs and removes its test directories; no real key is included.

## Run

With a payload JSON file:

```sh
node molt-event.mjs --key identity.json --ledger events.jsonl --type record.created --actor alice --payload payload.json
```

Without `--payload`, provide one JSON value on standard input:

```sh
printf '%s' '{"item":"book"}' | node molt-event.mjs --key identity.json --ledger events.jsonl --type record.created --actor alice
```

The command prints the canonical event as one JSON line after appending it to the ledger. It creates a missing ledger. Before appending to an existing ledger, it verifies every canonical Camp 1 event, the sequence and hash chain, and each Ed25519 signature. It rejects malformed, tampered, non-Camp-1, blank-line, non-newline-terminated, or mixed-key ledgers without modification, and it will not append with a different key. Use `molt-verify` for package-level actor-key binding and artifact validation.

## Identity files

`--key` accepts the two identity layouts used by `molt-sign`:

- Manifest signer: `{"manifest-signer":{"priv":"<64 lowercase hex>","pub":"<64 lowercase hex>"}}`
- `molt.ed25519-identity.v1`: an object with `schema: "molt.ed25519-identity.v1"`, `algorithm: "Ed25519"`, a non-empty `purpose`, `privateKeyHex`, `publicKeyHex`, and `keyId` (SHA-256 of the 32 raw public-key bytes)

For both layouts, the private value is a 32-byte Ed25519 seed and the public value is its 32-byte raw public key, represented as 64 lowercase hex characters. The tool derives the public key from the private seed and rejects a mismatch. It never prints or writes the private seed.

## Event format and formulas

Each ledger line is a canonical JSON object with exactly these fields:

- `seq`: zero-based sequence number, equal to the count of earlier non-empty ledger lines
- `ts`: current Unix time in whole seconds
- `type`, `actor`: the values supplied on the command line
- `payload`: any JSON value read from the payload file or stdin
- `prev_hash`: 64 zeroes for the first event; otherwise the prior event's `hash`
- `pub`: the signer's 32-byte raw public key as 64 lowercase hex characters
- `sig`: Ed25519 signature as 128 lowercase hex characters
- `hash`: SHA-256 digest as 64 lowercase hex characters

Camp 1 is the MOLT-CORE event scheme. The signed body contains exactly `seq`, `ts`, `type`, `payload`, and `actor`; `prev_hash`, `pub`, `sig`, and `hash` are not part of that body. `canonicalizeJsonText` canonicalizes the five-field body and the complete event.

Let `C` be the canonical body bytes and `P` the 64-character lowercase hexadecimal `prev_hash` text:

- `hash = lowercase_hex(SHA-256(UTF-8(P || C)))`
- `sig = lowercase_hex(Ed25519_sign(private_key, decode_hex(hash)))`

The signature covers the 32 raw hash bytes. The completed event is canonicalized and appended with one newline. This matches `molt-verify`, `molt-verify-ledger`, and the Camp 1 writer in `molt-audit` for ASCII event content. MOLT-CORE leaves non-ASCII canonicalization open; do not rely on cross-implementation agreement for non-ASCII fields until that ruling is settled.

## Pairing with molt-canonical and molt-sign

`molt-canonical.mjs` is the canonicalization implementation imported by this tool. The tool signs the raw 32-byte event hash with Node's built-in Ed25519 support and accepts the identity formats also used by `molt-sign`. To verify an event with `molt-sign`, pass the decoded hash bytes as the message. The event hash binds the previous event hash to the canonical five-field body. Before appending, this writer checks the existing ledger's Camp 1 chain and signatures. Use `molt-verify` for full package validation, including manifest bindings and artifacts.
