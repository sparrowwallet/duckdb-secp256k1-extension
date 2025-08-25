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
git clone https://github.com/your-repo/duckdb-secp256k1-extension.git
cd duckdb-secp256k1-extension
```

2. Initialize and update submodules:
```bash
git submodule update --init --recursive
```

3. Build the extension:
```bash
make
```

4. Run tests:
```bash
make test
```

The compiled extension will be available at `build/release/extension/secp256k1/secp256k1.duckdb_extension`.

### Loading the Extension

```sql
LOAD 'path/to/secp256k1.duckdb_extension';
```

## Functions

### Elliptic Curve Operations

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

### Cryptographic Hash Functions

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

### Data Conversion Functions

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
- DuckDB 1.3.2 or higher

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Examples

### Creating a Bitcoin Address Workflow

```sql
-- Generate a random 32-byte private key (in practice, use secure randomness)
WITH private_key AS (
    SELECT from_hex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') as privkey
),
public_key AS (
    SELECT secp256k1_ec_pubkey_create(privkey) as pubkey 
    FROM private_key
)
SELECT pubkey FROM public_key;
```

### Working with Transaction Outpoints

```sql
-- Create multiple outpoints and find the minimum
WITH outpoints AS (
    SELECT create_outpoint(from_hex('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'), 0) as out1,
           create_outpoint(from_hex('fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321'), 1) as out2
)
SELECT min_outpoint([out1, out2]) as min_outpoint FROM outpoints;
```