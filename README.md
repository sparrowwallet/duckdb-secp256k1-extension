# DuckDB secp256k1 Extension

A DuckDB extension that provides secp256k1 elliptic curve cryptography functions and Bitcoin-related utilities.
All cryptographic operations use the [libsecp256k1](https://github.com/bitcoin-core/secp256k1/) library.

## Building the Extension

### Prerequisites

- CMake 3.21 or higher
- C++ compiler with C++17 support
- Git

### Build Steps

1. Clone the repository:
```bash
git clone --recursive https://github.com/sparrowwallet/duckdb-secp256k1-extension.git
cd duckdb-secp256k1-extension
```

2. Build the extension:
```bash
make
```

3. Run tests:
```bash
make test
```

The compiled extension will be available at `build/release/extension/secp256k1/secp256k1.duckdb_extension`.
Running the compiled DuckDB binary at `build/release/duckdb` will run DuckDB with the extension already loaded.

### Loading the Extension

```sql
LOAD 'path/to/secp256k1.duckdb_extension';
```

## Functions

### Primary Function

#### `scan_silent_payments(outputs, keys, label_tweaks)`

Efficiently scans for Bitcoin Silent Payments (BIP 352) by combining multiple cryptographic operations into a single function. This function implements the core silent payments scanning algorithm, avoiding the serialization/deserialization overhead that would occur when using individual functions.

**Parameters:**
- `outputs` (LIST[BIGINT]): Array of 64-bit integers representing the first 8 bytes (big-endian) of output x-coordinates to scan for matches
- `keys` (LIST[BLOB]): Array containing exactly 3 elements: [scan_private_key (32 bytes), spend_public_key (33 or 64 bytes), tweak_key (33 or 64 bytes)]
- `label_tweaks` (LIST[BLOB]): Array of compressed public keys (33 bytes) or raw secp256k1_pubkey structs (64 bytes) representing label tweak keys for labeled outputs (can be empty)

If public keys are provided as 64 bytes, they must be in little endian format with the x-value first, followed by the y value.

**Returns:** BOOLEAN (true if any matching output is found, false otherwise)

**Algorithm:**
1. **Tweak Multiplication**: Multiplies the tweak_key by the scan_private_key using `secp256k1_ec_pubkey_tweak_mul(tweak_key, scan_private_key)`
2. **Base Shared Secret**: Computes the base shared secret using `secp256k1_tagged_sha256('BIP0352/SharedSecret', tweaked_key || int_to_big_endian(0))`
3. **Base Output Key**: Creates base output key by combining spend_public_key with the public key derived from the base shared secret
4. **Direct Match Check**: Extracts first 8 bytes of base output key's x-coordinate and checks against the outputs list
5. **Label Tweak Processing**: For each label tweak key:
   - Combines the base output key with the label tweak key using elliptic curve addition
   - Checks if the combined result matches any output in the list
   - Also checks the negated version of the combined result (covers both possible y-coordinates)
6. **Early Return**: Returns true immediately upon finding any match

**Example:**
```sql
-- Basic silent payments scanning without label tweaks
WITH 
  scan_priv AS (SELECT from_hex('0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c') as key),
  spend_pub AS (SELECT from_hex('36cf8fcd4d4890ab6c1083aeb5b50c260c20acda7839120e3575836f6d85c95ce0d705e31ff9fdcce67a8f3598871c6dfbe6bcde8a51cb7b48b0f95be0ea94de') as key),
  tweak_key AS (SELECT from_hex('040096db612390ee6cef521e784c897c446a26cea8e28819962e5316c253c24a501e53f71071162afab559954064f0ccb7a6779c23b305597b6335829cc1f5b7') as key),
  
  -- Outputs to scan (first 8 bytes of x-coordinates as BIGINT)
  outputs_to_scan AS (SELECT [hash_prefix_to_int(from_hex('3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1'), 0)] as list),
  keys AS (SELECT [(SELECT key FROM scan_priv), (SELECT key FROM spend_pub), (SELECT key FROM tweak_key)] as keys_array)
SELECT scan_silent_payments(
    (SELECT list FROM outputs_to_scan),
    (SELECT keys_array FROM keys),
    CAST([] AS BLOB[])  -- No label tweaks
); -- Returns: true/false depending on whether any output matches

-- Silent payments scanning with label tweaks
WITH 
  scan_priv AS (SELECT from_hex('0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c') as key),
  spend_pub AS (SELECT from_hex('36cf8fcd4d4890ab6c1083aeb5b50c260c20acda7839120e3575836f6d85c95ce0d705e31ff9fdcce67a8f3598871c6dfbe6bcde8a51cb7b48b0f95be0ea94de') as key),
  tweak_key AS (SELECT from_hex('040096db612390ee6cef521e784c897c446a26cea8e28819962e5316c253c24a501e53f71071162afab559954064f0ccb7a6779c23b305597b6335829cc1f5b7') as key),
  
  -- Label tweak keys for labeled outputs
  label_tweaks AS (SELECT [
    from_hex('cd63f9212a2deebde8a71e9ea23f6f958c47c41d2ed74b9617fe6fb554d1524e292fabddbdcbb643eafc328875c46d75a1d697b2b31c42d38aa93f85eab34bc1')
  ] as tweaks),
  
  outputs_to_scan AS (SELECT [hash_prefix_to_int(from_hex('3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1'), 0)] as list),
  keys AS (SELECT [(SELECT key FROM scan_priv), (SELECT key FROM spend_pub), (SELECT key FROM tweak_key)] as keys_array)
SELECT scan_silent_payments(
    (SELECT list FROM outputs_to_scan),
    (SELECT keys_array FROM keys),
    (SELECT tweaks FROM label_tweaks)
); -- Returns: true if any output (base or labeled) matches

-- Equivalent to this complex multi-function SQL (but much more efficient):
-- SELECT secp256k1_xonly_key_match(
--     outputs,
--     secp256k1_ec_pubkey_combine([
--         spend_public_key,
--         secp256k1_ec_pubkey_create(secp256k1_tagged_sha256('BIP0352/SharedSecret', 
--             secp256k1_ec_pubkey_tweak_mul(tweak_key, scan_private_key) || int_to_big_endian(0)))
--     ]),
--     label_tweak_keys
-- );
```

**Performance Benefits:**
- **Reduced Overhead**: Eliminates serialization/deserialization between individual secp256k1 function calls
- **Memory Efficiency**: Operates on internal secp256k1 data structures without intermediate conversions
- **Atomic Operation**: Single function call handles entire scanning workflow
- **Early Termination**: Returns immediately upon finding first match, avoiding unnecessary computations
- **Flexible Key Formats**: Accepts both 33-byte compressed keys and 64-byte raw secp256k1_pubkey structs for maximum efficiency

**Key Format Support:**
- **33-byte compressed keys**: Parsed using `secp256k1_ec_pubkey_parse()` 
- **64-byte raw structs**: Cast directly to `secp256k1_pubkey` without parsing overhead for maximum performance
- **Automatic detection**: Function automatically detects format based on byte length

### Debugging and Advanced Functions

The following functions are exposed for debugging, testing, and building custom scanning logic. In most cases, you should use `scan_silent_payments` instead, as it's optimized for performance and combines these operations efficiently.

#### `secp256k1_xonly_key_match(xonly_prefixes, target_compressed, compressed_keys)`

Checks if a target compressed public key can be found either directly by matching its x-coordinate's first 8 bytes (big-endian) against a list of BIGINT prefixes, or by combining the target with compressed public keys from a second list and comparing the result. This function is useful for Bitcoin Silent Payments and other protocols that need to scan for key matches with elliptic curve operations.

**Parameters:**
- `xonly_prefixes` (LIST[BIGINT]): Array of 64-bit integers representing the first 8 bytes (big-endian) of x-only public keys to search in
- `target_compressed` (BLOB): 33-byte target compressed public key
- `compressed_keys` (LIST[BLOB]): Array of 33-byte compressed public keys to combine with target

**Returns:** BOOLEAN (true if match found, false otherwise)

**Behavior:**
1. Extracts first 8 bytes (big-endian) of `target_compressed` key's x-coordinate as a BIGINT prefix
2. First checks for direct match of this prefix against the `xonly_prefixes` list
3. If no direct match, iterates through `compressed_keys` list:
   - For each compressed key, combines it with `target_compressed` using elliptic curve addition
   - Extracts x-coordinate of result and converts first 8 bytes to BIGINT prefix
   - Compares this prefix to all values in `xonly_prefixes` list
   - Also tries negated version of compressed key (covers both possible y-coordinates)
   - Returns true on first match found
4. Returns false if no matches found after checking all combinations

**Example:**
```sql
-- Direct match test using BIGINT prefixes
WITH test_data AS (
    SELECT
        from_hex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798') as x_only_key,
        from_hex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798') as compressed_key
)
SELECT secp256k1_xonly_key_match(
    [hash_prefix_to_int(x_only_key, 0)],  -- BIGINT[] with first 8 bytes of key as big-endian int
    compressed_key,                       -- Target compressed key
    []                                    -- Empty compressed keys
) FROM test_data; -- Returns: true

-- Key combination test (G + 2G = 3G scenario)
WITH test_keys AS (
    SELECT
        secp256k1_ec_pubkey_create(from_hex('0000000000000000000000000000000000000000000000000000000000000001')) as g_point,
        secp256k1_ec_pubkey_create(from_hex('0000000000000000000000000000000000000000000000000000000000000002')) as double_g,
        secp256k1_ec_pubkey_create(from_hex('0000000000000000000000000000000000000000000000000000000000000003')) as triple_g
),
x_coords AS (
    SELECT
        from_hex(substring(to_hex(g_point), 3, 64)) as g_x,
        from_hex(substring(to_hex(triple_g), 3, 64)) as triple_g_x,
        double_g
    FROM test_keys
)
SELECT secp256k1_xonly_key_match(
    [hash_prefix_to_int(triple_g_x, 0)],  -- BIGINT[] with first 8 bytes of 3G x-coordinate
    g_point,                              -- Target: G point as compressed key
    [double_g]                            -- Compressed keys: 2G (G + 2G = 3G should match)
) FROM x_coords; -- Returns: true
```

#### `secp256k1_ec_pubkey_create(secret_key)`

Creates a public key from a 32-byte secret key.

**Parameters:**
- `secret_key` (BLOB): 32-byte secret key

**Returns:** BLOB (33-byte compressed public key)

**Example:**
```sql
SELECT secp256k1_ec_pubkey_create(from_hex('0000000000000000000000000000000000000000000000000000000000000001'));
```

#### `secp256k1_ec_pubkey_combine(public_keys)`

Combines multiple public keys using elliptic curve addition.

**Parameters:**
- `public_keys` (LIST[BLOB]): Array of 33-byte compressed public keys

**Returns:** BLOB (33-byte compressed combined public key)

**Example:**
```sql
SELECT secp256k1_ec_pubkey_combine([
    from_hex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
    from_hex('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
]);
```

#### `secp256k1_ec_pubkey_tweak_mul(public_key, tweak)`

Tweaks a public key by scalar multiplication.

**Parameters:**
- `public_key` (BLOB): 33-byte compressed public key
- `tweak` (BLOB): 32-byte scalar value

**Returns:** BLOB (33-byte compressed tweaked public key)

**Example:**
```sql
SELECT secp256k1_ec_pubkey_tweak_mul(
    from_hex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
    from_hex('0000000000000000000000000000000000000000000000000000000000000002')
);
```

#### `secp256k1_tagged_sha256(tag, message)`

Computes a tagged SHA256 hash as defined in BIP 340.

**Parameters:**
- `tag` (VARCHAR): Tag string
- `message` (BLOB or VARCHAR): Message to hash

**Returns:** BLOB (32-byte hash)

**Example:**
```sql
SELECT secp256k1_tagged_sha256('BIP0340/challenge', 'test message');
```

#### `hash_prefix_to_int(blob, offset)`

Extracts 8 bytes from a blob starting at an offset and converts to a signed 64-bit integer (big-endian).

**Parameters:**
- `blob` (BLOB): Input binary data
- `offset` (UINTEGER): Byte offset to start reading from

**Returns:** BIGINT (64-bit signed integer)

**Example:**
```sql
-- Read from beginning of a 32-byte hash
SELECT hash_prefix_to_int(from_hex('FFFFFFFFFFFFFFFF000000000000000000000000000000000000000000000000'), 0);
-- Returns: -1

-- Read from byte offset 8
SELECT hash_prefix_to_int(from_hex('00000000000000000000000000000001000000000000000000000000000000'), 8);
-- Returns: 1
```

#### `int_to_big_endian(value)`

Converts a 32-bit integer to a 4-byte big-endian blob.

**Parameters:**
- `value` (INTEGER): 32-bit signed integer

**Returns:** BLOB (4-byte big-endian representation)

**Example:**
```sql
SELECT int_to_big_endian(1234567890);
-- Returns: \x499602d2

SELECT int_to_big_endian(-1);
-- Returns: \xffffffff
```

### Bitcoin Utility Functions

#### `create_outpoint(txid, vout)`

Creates a Bitcoin outpoint by concatenating a transaction ID with a transaction output index.

**Parameters:**
- `txid` (BLOB): 32-byte transaction ID
- `vout` (INTEGER): Transaction output index (32-bit)

**Returns:** BLOB (36-byte outpoint: reversed txid + little-endian vout)

**Example:**
```sql
SELECT create_outpoint(
    from_hex('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'),
    0
);
```

#### `min_outpoint(outpoints)`

Finds the lexicographically smallest outpoint from a list.

**Parameters:**
- `outpoints` (LIST[BLOB]): Array of 36-byte outpoints

**Returns:** BLOB (36-byte outpoint with smallest lexicographic value)

**Example:**
```sql
SELECT min_outpoint([
    from_hex('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00000000'),
    from_hex('fedcba0987654321fedcba0987654321fedcba0987654321fedcba098765432100000000')
]);
```

## Error Handling

All functions return `NULL` when:
- Input parameters are `NULL`
- Input data has incorrect size/format
- Cryptographic operations fail (e.g., invalid keys, point at infinity)
- Buffer boundaries are exceeded

## Security Considerations

- This extension uses the libsecp256k1 library for cryptographic operations
- All functions perform input validation to prevent buffer overflows
- Memory access is handled safely through DuckDB's execution framework
- No private key material is logged or exposed in error messages

## Dependencies

- [libsecp256k1](https://github.com/bitcoin-core/secp256k1): Optimized C library for secp256k1 elliptic curve operations
- DuckDB 1.4.1

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request
