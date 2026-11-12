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

The command prints the canonical event as one JSON line after appending it to the ledger. It creates a missing ledger. Errors go to stderr, return a non-zero exit status, and do not append an event. Existing non-empty ledger lines must each be valid JSON objects with a 64-character lowercase hexadecimal `hash` field. The tool counts non-empty lines for the next sequence number and uses the last event's hash as `prev_hash`; it does not independently verify the prior events' signatures or the complete chain.

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

The body contains `seq`, `ts`, `type`, `actor`, `payload`, `prev_hash`, and `pub`, with no `sig` or `hash`. The attached `canonicalizeJsonText` function from `molt-canonical.mjs` canonicalizes both the body and the complete event.

Let `C` be the canonical body string and `P` be the `prev_hash` string:

- `hash = lowercase_hex(SHA-256(UTF-8(P || C)))`
- `sig = lowercase_hex(Ed25519_sign(private_key, UTF-8(C)))`

The hash concatenation uses the 64-character hexadecimal text of `prev_hash`, followed directly by the canonical body bytes. The signature covers only the canonical body bytes, not the hash or full event. The completed event is canonicalized, then appended with one newline.

## Pairing with molt-canonical and molt-sign

`molt-canonical.mjs` is the canonicalization implementation imported by this tool. The event tool then signs the exact canonical body bytes with Node's built-in Ed25519 support, following the same identity formats and signing primitive as `molt-sign`. `molt-sign` can verify the event's signature by extracting the event body, canonicalizing it with `molt-canonical`, and verifying against `pub`. The event `hash` additionally binds the previous event hash to the body. Use the separate MOLT L1 verifier when you need to validate a whole ledger; this append tool is not a ledger verifier.
