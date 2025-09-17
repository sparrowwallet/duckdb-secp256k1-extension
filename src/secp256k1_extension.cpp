#define DUCKDB_EXTENSION_MAIN

#include "secp256k1_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

// secp256k1 library
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#include <vector>
#include <memory>
#include <cstring>

namespace duckdb {

// Global secp256k1 context for verification operations
static secp256k1_context *secp256k1_ctx = nullptr;

// Helper function to initialize secp256k1 context
static secp256k1_context *GetSecp256k1Context() {
	if (!secp256k1_ctx) {
		secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
		if (!secp256k1_ctx) {
			throw InternalException("Failed to create secp256k1 context");
		}
	}
	return secp256k1_ctx;
}

// Function to combine public keys using secp256k1_ec_pubkey_combine
inline void Secp256k1EcPubkeyCombineScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	// The function takes a single LIST argument containing BLOB elements (each 33 bytes for compressed pubkeys)
	D_ASSERT(args.ColumnCount() == 1);

	auto &list_vector = args.data[0];

	UnaryExecutor::ExecuteWithNulls<list_entry_t, string_t>(
	    list_vector, result, args.size(), [&](list_entry_t list_data, ValidityMask &mask, idx_t idx) {
		    // Get the child vector (contains the actual BLOB elements)
		    auto &child_vector = ListVector::GetEntry(list_vector);

		    std::vector<secp256k1_pubkey> parsed_pubkeys;
		    std::vector<const secp256k1_pubkey *> pubkey_ptrs;

		    bool all_valid = true;

		    // Check if list is empty
		    if (list_data.length == 0) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Parse all public keys in the list for this row
		    for (idx_t j = 0; j < list_data.length; j++) {
			    idx_t child_idx = list_data.offset + j;

			    // Check if this list element is NULL
			    if (FlatVector::IsNull(child_vector, child_idx)) {
				    all_valid = false;
				    break;
			    }

			    // Get the blob data
			    auto blob_data = FlatVector::GetData<string_t>(child_vector)[child_idx];

			    // Validate that the blob is exactly 33 bytes (compressed pubkey format)
			    if (blob_data.GetSize() != 33) {
				    all_valid = false;
				    break;
			    }

			    // Parse the public key
			    secp256k1_pubkey pubkey;
			    if (secp256k1_ec_pubkey_parse(ctx, &pubkey, (const unsigned char *)blob_data.GetData(), 33) != 1) {
				    all_valid = false;
				    break;
			    }

			    parsed_pubkeys.push_back(pubkey);
		    }

		    if (!all_valid || parsed_pubkeys.empty()) {
			    // Set result to NULL for this row
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Create array of pointers for secp256k1_ec_pubkey_combine
		    for (const auto &pk : parsed_pubkeys) {
			    pubkey_ptrs.push_back(&pk);
		    }

		    // Combine the public keys
		    secp256k1_pubkey combined_pubkey;
		    if (secp256k1_ec_pubkey_combine(ctx, &combined_pubkey, pubkey_ptrs.data(), pubkey_ptrs.size()) != 1) {
			    // Set result to NULL for this row if combination failed
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Serialize the combined public key back to compressed format (33 bytes)
		    unsigned char output[33];
		    size_t output_len = 33;

		    if (secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &combined_pubkey, SECP256K1_EC_COMPRESSED) !=
		        1) {
			    // Set result to NULL for this row if serialization failed
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Create and return the result blob
		    return StringVector::AddStringOrBlob(result, (const char *)output, 33);
	    });
}

// Function to concatenate a 32-byte blob with a 4-byte integer in little-endian format
inline void CreateOutpointScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 2);

	BinaryExecutor::ExecuteWithNulls<string_t, int32_t, string_t>(
	    args.data[0], args.data[1], result, args.size(),
	    [&](string_t blob_data, int32_t int_value, ValidityMask &mask, idx_t idx) {
		    // Validate that the blob is exactly 32 bytes
		    if (blob_data.GetSize() != 32) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Create output buffer (32 bytes + 4 bytes = 36 bytes)
		    unsigned char output[36];

		    // Copy the 32-byte blob in reverse order (big-endian to little-endian)
		    const unsigned char *input_data = (const unsigned char *)blob_data.GetData();
		    for (int j = 0; j < 32; j++) {
			    output[j] = input_data[31 - j];
		    }

		    // Append the 4-byte integer in little-endian format
		    output[32] = (unsigned char)(int_value & 0xFF);
		    output[33] = (unsigned char)((int_value >> 8) & 0xFF);
		    output[34] = (unsigned char)((int_value >> 16) & 0xFF);
		    output[35] = (unsigned char)((int_value >> 24) & 0xFF);

		    // Create and return the result blob
		    return StringVector::AddStringOrBlob(result, (const char *)output, 36);
	    });
}

// Function to find the lexicographically smallest 36-byte blob
inline void MinOutpointScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	// The function takes a single LIST argument containing BLOB elements (each 36 bytes for outpoints)
	D_ASSERT(args.ColumnCount() == 1);

	auto &list_vector = args.data[0];

	UnaryExecutor::ExecuteWithNulls<list_entry_t, string_t>(
	    list_vector, result, args.size(), [&](list_entry_t list_data, ValidityMask &mask, idx_t idx) {
		    // Get the child vector (contains the actual BLOB elements)
		    auto &child_vector = ListVector::GetEntry(list_vector);

		    string_t min_blob;
		    bool found_valid = false;

		    // Check if list is empty
		    if (list_data.length == 0) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Check all blobs in the list for this row
		    for (idx_t j = 0; j < list_data.length; j++) {
			    idx_t child_idx = list_data.offset + j;

			    // Check if this list element is NULL
			    if (FlatVector::IsNull(child_vector, child_idx)) {
				    continue;
			    }

			    // Get the blob data
			    auto blob_data = FlatVector::GetData<string_t>(child_vector)[child_idx];

			    // Validate that the blob is exactly 36 bytes
			    if (blob_data.GetSize() != 36) {
				    continue;
			    }

			    // If this is the first valid blob, use it as the minimum
			    if (!found_valid) {
				    min_blob = blob_data;
				    found_valid = true;
			    } else {
				    // Compare lexicographically (memcmp does lexicographic comparison for bytes)
				    if (memcmp(blob_data.GetData(), min_blob.GetData(), 36) < 0) {
					    min_blob = blob_data;
				    }
			    }
		    }

		    if (!found_valid) {
			    // Set result to NULL if no valid 36-byte blobs found
			    mask.SetInvalid(idx);
			    return string_t();
		    } else {
			    // Create and return the result blob by copying the minimum blob
			    return StringVector::AddStringOrBlob(result, (const char *)min_blob.GetData(), 36);
		    }
	    });
}

// Function to compute secp256k1 tagged SHA256 hash
inline void Secp256k1TaggedSha256ScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 2);

	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	BinaryExecutor::ExecuteWithNulls<string_t, string_t, string_t>(
	    args.data[0], args.data[1], result, args.size(),
	    [&](string_t tag_data, string_t msg_data, ValidityMask &mask, idx_t idx) {
		    // Copy the string data immediately to avoid any pointer issues
		    std::string tag_str = tag_data.GetString();
		    std::string msg_str = msg_data.GetString();

		    // Create output buffer for 32-byte hash
		    unsigned char hash32[32];

		    // Call secp256k1_tagged_sha256 with copied string data
		    int result_code =
		        secp256k1_tagged_sha256(ctx, hash32, (const unsigned char *)tag_str.c_str(), tag_str.size(),
		                                (const unsigned char *)msg_str.c_str(), msg_str.size());

		    if (result_code != 1) {
			    // Set result to NULL if hashing failed (though this should always succeed)
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Create and return the result blob
		    return StringVector::AddStringOrBlob(result, (const char *)hash32, 32);
	    });
}

// Function to tweak a public key by scalar multiplication
inline void Secp256k1EcPubkeyTweakMulScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 2);

	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	BinaryExecutor::ExecuteWithNulls<string_t, string_t, string_t>(
	    args.data[0], args.data[1], result, args.size(),
	    [&](string_t pubkey_data, string_t tweak_data, ValidityMask &mask, idx_t idx) {
		    // Validate that the public key is exactly 33 bytes (compressed format)
		    if (pubkey_data.GetSize() != 33) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Validate that the tweak is exactly 32 bytes
		    if (tweak_data.GetSize() != 32) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Parse the public key
		    secp256k1_pubkey pubkey;
		    if (secp256k1_ec_pubkey_parse(ctx, &pubkey, (const unsigned char *)pubkey_data.GetData(), 33) != 1) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Apply the scalar tweak
		    if (secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, (const unsigned char *)tweak_data.GetData()) != 1) {
			    // Tweak failed (invalid tweak or resulting point at infinity)
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Serialize the tweaked public key back to compressed format (33 bytes)
		    unsigned char output[33];
		    size_t output_len = 33;

		    if (secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &pubkey, SECP256K1_EC_COMPRESSED) != 1) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Create and return the result blob
		    return StringVector::AddStringOrBlob(result, (const char *)output, 33);
	    });
}

// Function to create a public key from a secret key using secp256k1_ec_pubkey_create
inline void Secp256k1EcPubkeyCreateScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 1);

	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	UnaryExecutor::ExecuteWithNulls<string_t, string_t>(
	    args.data[0], result, args.size(), [&](string_t seckey_data, ValidityMask &mask, idx_t idx) {
		    // Validate that the secret key is exactly 32 bytes
		    if (seckey_data.GetSize() != 32) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Create the public key
		    secp256k1_pubkey pubkey;
		    if (secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char *)seckey_data.GetData()) != 1) {
			    // Secret key is invalid (zero, out of range, etc.)
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Serialize the public key to compressed format (33 bytes)
		    unsigned char output[33];
		    size_t output_len = 33;

		    if (secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &pubkey, SECP256K1_EC_COMPRESSED) != 1) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }

		    // Create and return the result blob
		    return StringVector::AddStringOrBlob(result, (const char *)output, 33);
	    });
}

// Function to convert bytes from a blob to a bigint with most significant byte first, starting at an offset
inline void HashPrefixToIntScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 2);

	BinaryExecutor::ExecuteWithNulls<string_t, uint32_t, int64_t>(
	    args.data[0], args.data[1], result, args.size(),
	    [&](string_t blob_data, uint32_t offset, ValidityMask &mask, idx_t idx) {
		    // Validate that the blob is long enough (offset + 8 bytes needed)
		    if (blob_data.GetSize() < offset + 8) {
			    mask.SetInvalid(idx);
			    return int64_t(0);
		    }

		    // Read directly from blob data starting at offset
		    const unsigned char *input_data = (const unsigned char *)blob_data.GetData() + offset;

		    // Convert to bigint (big-endian, most significant byte first)
		    // Take 8 bytes starting from the offset
		    int64_t result_value = 0;
		    for (int j = 0; j < 8; j++) {
			    result_value = (result_value << 8) | input_data[j];
		    }

		    return result_value;
	    });
}

// Function to convert an integer to a 4-byte blob in big-endian format (MSB first)
inline void IntegerToBigEndianScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 1);

	UnaryExecutor::Execute<int32_t, string_t>(args.data[0], result, args.size(), [&](int32_t int_value) {
		// Create output buffer (4 bytes)
		unsigned char output[4];

		// Store the integer in big-endian format (most significant byte first)
		output[0] = (unsigned char)((int_value >> 24) & 0xFF); // MSB
		output[1] = (unsigned char)((int_value >> 16) & 0xFF);
		output[2] = (unsigned char)((int_value >> 8) & 0xFF);
		output[3] = (unsigned char)(int_value & 0xFF); // LSB

		// Create and return the result blob
		return StringVector::AddStringOrBlob(result, (const char *)output, 4);
	});
}

// Helper function to extract first 8 bytes as big-endian int64
static int64_t ExtractBigEndianInt64(const unsigned char *data) {
	int64_t result = 0;
	for (int i = 0; i < 8; i++) {
		result = (result << 8) | data[i];
	}
	return result;
}

// Function to check if compressed key exists in list with compressed key combinations
inline void Secp256k1XOnlyKeyMatchScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 3);

	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	TernaryExecutor::ExecuteWithNulls<list_entry_t, string_t, list_entry_t, bool>(
	    args.data[0], args.data[1], args.data[2], result, args.size(),
	    [&](list_entry_t xonly_list, string_t target_compressed, list_entry_t compressed_list, ValidityMask &mask,
	        idx_t idx) {
		    // Validate target compressed key is exactly 33 bytes
		    if (target_compressed.GetSize() != 33) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Extract first 8 bytes of target compressed key's x-coordinate as big-endian int64
		    // Skip the first byte (compression flag) and take bytes 1-8
		    int64_t target_prefix = ExtractBigEndianInt64((const unsigned char *)target_compressed.GetData() + 1);

		    // Get the child vectors
		    auto &xonly_child_vector = ListVector::GetEntry(args.data[0]);
		    auto &compressed_child_vector = ListVector::GetEntry(args.data[2]);

		    // First, check for direct match in the x-only list (now comparing BIGINT values)
		    for (idx_t j = 0; j < xonly_list.length; j++) {
			    idx_t child_idx = xonly_list.offset + j;

			    // Skip NULL elements
			    if (FlatVector::IsNull(xonly_child_vector, child_idx)) {
				    continue;
			    }

			    // Get the BIGINT value from the list
			    auto xonly_int64 = FlatVector::GetData<int64_t>(xonly_child_vector)[child_idx];

			    // Direct comparison of first 8 bytes as BIGINT
			    if (xonly_int64 == target_prefix) {
				    return true;
			    }
		    }

		    // Only parse the target compressed key if we need to do combinations
		    if (compressed_list.length == 0) {
			    // No compressed keys to combine, and no direct match found
			    return false;
		    }

		    // Parse the target compressed key for combination operations
		    secp256k1_pubkey target_pubkey;
		    if (secp256k1_ec_pubkey_parse(ctx, &target_pubkey, (const unsigned char *)target_compressed.GetData(),
		                                  33) != 1) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // If no direct match, iterate through compressed keys list
		    for (idx_t k = 0; k < compressed_list.length; k++) {
			    idx_t compressed_idx = compressed_list.offset + k;

			    // Skip NULL elements
			    if (FlatVector::IsNull(compressed_child_vector, compressed_idx)) {
				    continue;
			    }

			    auto compressed_blob = FlatVector::GetData<string_t>(compressed_child_vector)[compressed_idx];

			    // Validate that this compressed key is exactly 33 bytes
			    if (compressed_blob.GetSize() != 33) {
				    continue;
			    }

			    // Parse the compressed public key
			    secp256k1_pubkey compressed_pk;
			    if (secp256k1_ec_pubkey_parse(ctx, &compressed_pk, (const unsigned char *)compressed_blob.GetData(),
			                                  33) != 1) {
				    continue;
			    }

			    // Combine the target compressed key with the current compressed key
			    const secp256k1_pubkey *pubkeys[2] = {&target_pubkey, &compressed_pk};
			    secp256k1_pubkey combined_pubkey;
			    if (secp256k1_ec_pubkey_combine(ctx, &combined_pubkey, pubkeys, 2) != 1) {
				    continue;
			    }

			    // Serialize the combined key to compressed format
			    unsigned char combined_compressed[33];
			    size_t combined_len = 33;
			    if (secp256k1_ec_pubkey_serialize(ctx, combined_compressed, &combined_len, &combined_pubkey,
			                                      SECP256K1_EC_COMPRESSED) != 1) {
				    continue;
			    }

			    // Extract first 8 bytes of combined x-coordinate as big-endian int64
			    // Skip the first byte (compression flag) and take bytes 1-8
			    int64_t combined_prefix = ExtractBigEndianInt64(combined_compressed + 1);

			    // Check if this combined x value matches any in the first list
			    for (idx_t j = 0; j < xonly_list.length; j++) {
				    idx_t child_idx = xonly_list.offset + j;

				    if (FlatVector::IsNull(xonly_child_vector, child_idx)) {
					    continue;
				    }

				    // Get the BIGINT value from the list
				    auto xonly_int64 = FlatVector::GetData<int64_t>(xonly_child_vector)[child_idx];

				    // Compare first 8 bytes as BIGINT
				    if (xonly_int64 == combined_prefix) {
					    return true;
				    }
			    }

			    // Try with negated result of the addition
			    secp256k1_pubkey negated_combined_pubkey = combined_pubkey;
			    if (secp256k1_ec_pubkey_negate(ctx, &negated_combined_pubkey) != 1) {
				    continue;
			    }

			    // Serialize the negated combined key to compressed format
			    unsigned char negated_combined_compressed[33];
			    size_t negated_combined_len = 33;
			    if (secp256k1_ec_pubkey_serialize(ctx, negated_combined_compressed, &negated_combined_len,
			                                      &negated_combined_pubkey, SECP256K1_EC_COMPRESSED) != 1) {
				    continue;
			    }

			    // Extract first 8 bytes of negated combined x-coordinate as big-endian int64
			    // Skip the first byte (compression flag) and take bytes 1-8
			    int64_t negated_combined_prefix = ExtractBigEndianInt64(negated_combined_compressed + 1);

			    // Check if this negated combined x value matches any in the first list
			    for (idx_t j = 0; j < xonly_list.length; j++) {
				    idx_t child_idx = xonly_list.offset + j;

				    if (FlatVector::IsNull(xonly_child_vector, child_idx)) {
					    continue;
				    }

				    // Get the BIGINT value from the list
				    auto xonly_int64 = FlatVector::GetData<int64_t>(xonly_child_vector)[child_idx];

				    // Compare first 8 bytes as BIGINT
				    if (xonly_int64 == negated_combined_prefix) {
					    return true;
				    }
			    }
		    }

		    return false;
	    });
}

// Function to scan for silent payments
inline void ScanSilentPaymentsScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 3);

	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	TernaryExecutor::ExecuteWithNulls<list_entry_t, list_entry_t, list_entry_t, bool>(
	    args.data[0], args.data[1], args.data[2], result, args.size(),
	    [&](list_entry_t outputs_list, list_entry_t keys_list, list_entry_t label_tweaks_list, ValidityMask &mask,
	        idx_t idx) {
		    // Get the child vectors
		    auto &outputs_child_vector = ListVector::GetEntry(args.data[0]);
		    auto &keys_child_vector = ListVector::GetEntry(args.data[1]);
		    auto &label_tweaks_child_vector = ListVector::GetEntry(args.data[2]);

		    // Validate that keys list has exactly 3 elements
		    if (keys_list.length != 3) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Extract the three keys: scan private key, spend public key, and tweak key
		    idx_t scan_key_idx = keys_list.offset;
		    idx_t spend_key_idx = keys_list.offset + 1;
		    idx_t tweak_key_idx = keys_list.offset + 2;

		    if (FlatVector::IsNull(keys_child_vector, scan_key_idx) ||
		        FlatVector::IsNull(keys_child_vector, spend_key_idx) ||
		        FlatVector::IsNull(keys_child_vector, tweak_key_idx)) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    auto scan_private_key = FlatVector::GetData<string_t>(keys_child_vector)[scan_key_idx];
		    auto spend_public_key = FlatVector::GetData<string_t>(keys_child_vector)[spend_key_idx];
		    auto tweak_key = FlatVector::GetData<string_t>(keys_child_vector)[tweak_key_idx];

		    // Validate key sizes
		    if (scan_private_key.GetSize() != 32 || spend_public_key.GetSize() != 33 || tweak_key.GetSize() != 33) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Parse the spend public key once
		    secp256k1_pubkey spend_pubkey;
		    if (secp256k1_ec_pubkey_parse(ctx, &spend_pubkey, (const unsigned char *)spend_public_key.GetData(), 33) !=
		        1) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Parse the tweak key
		    secp256k1_pubkey tweak_pubkey;
		    if (secp256k1_ec_pubkey_parse(ctx, &tweak_pubkey, (const unsigned char *)tweak_key.GetData(), 33) != 1) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Implement: secp256k1_ec_pubkey_tweak_mul(tweak_key, SILENT_PAYMENTS_SCAN_PRIVATE_KEY)
		    if (secp256k1_ec_pubkey_tweak_mul(ctx, &tweak_pubkey, (const unsigned char *)scan_private_key.GetData()) !=
		        1) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Serialize the tweaked key
		    unsigned char tweaked_key_serialized[33];
		    size_t tweaked_len = 33;
		    if (secp256k1_ec_pubkey_serialize(ctx, tweaked_key_serialized, &tweaked_len, &tweak_pubkey,
		                                      SECP256K1_EC_COMPRESSED) != 1) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Calculate the base shared secret: secp256k1_tagged_sha256('BIP0352/SharedSecret', tweaked_key ||
		    // int_to_big_endian(0))
		    std::string tag = "BIP0352/SharedSecret";

		    // Concatenate tweaked_key_serialized + int_to_big_endian(0)
		    unsigned char base_data[37]; // 33 + 4 bytes
		    memcpy(base_data, tweaked_key_serialized, 33);
		    // int_to_big_endian(0) = {0, 0, 0, 0}
		    base_data[33] = 0;
		    base_data[34] = 0;
		    base_data[35] = 0;
		    base_data[36] = 0;

		    // Compute base shared secret
		    unsigned char base_shared_secret[32];
		    if (secp256k1_tagged_sha256(ctx, base_shared_secret, (const unsigned char *)tag.c_str(), tag.size(),
		                                base_data, 37) != 1) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Create public key from base shared secret
		    secp256k1_pubkey base_shared_pubkey;
		    if (secp256k1_ec_pubkey_create(ctx, &base_shared_pubkey, base_shared_secret) != 1) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Combine with spend public key to get base output key
		    const secp256k1_pubkey *base_pubkeys[2] = {&spend_pubkey, &base_shared_pubkey};
		    secp256k1_pubkey base_output_key;
		    if (secp256k1_ec_pubkey_combine(ctx, &base_output_key, base_pubkeys, 2) != 1) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Serialize the base output key to compressed format
		    unsigned char base_compressed[33];
		    size_t base_len = 33;
		    if (secp256k1_ec_pubkey_serialize(ctx, base_compressed, &base_len, &base_output_key,
		                                      SECP256K1_EC_COMPRESSED) != 1) {
			    mask.SetInvalid(idx);
			    return false;
		    }

		    // Extract first 8 bytes of base x-coordinate as big-endian int64
		    int64_t base_prefix = ExtractBigEndianInt64(base_compressed + 1);

		    // Check direct match against outputs list
		    for (idx_t j = 0; j < outputs_list.length; j++) {
			    idx_t output_idx = outputs_list.offset + j;

			    if (FlatVector::IsNull(outputs_child_vector, output_idx)) {
				    continue;
			    }

			    auto output_int64 = FlatVector::GetData<int64_t>(outputs_child_vector)[output_idx];
			    if (output_int64 == base_prefix) {
				    return true;
			    }
		    }

		    // If no label tweaks provided, we're done (no match found)
		    if (label_tweaks_list.length == 0) {
			    return false;
		    }

		    // Process each label tweak by adding it to the base output key
		    for (idx_t k = 0; k < label_tweaks_list.length; k++) {
			    idx_t label_idx = label_tweaks_list.offset + k;

			    if (FlatVector::IsNull(label_tweaks_child_vector, label_idx)) {
				    continue;
			    }

			    auto label_tweak = FlatVector::GetData<string_t>(label_tweaks_child_vector)[label_idx];

			    // Validate that the label tweak is exactly 33 bytes (compressed pubkey)
			    if (label_tweak.GetSize() != 33) {
				    continue;
			    }

			    // Parse the label tweak public key
			    secp256k1_pubkey label_tweak_pubkey;
			    if (secp256k1_ec_pubkey_parse(ctx, &label_tweak_pubkey, (const unsigned char *)label_tweak.GetData(),
			                                  33) != 1) {
				    continue;
			    }

			    // Combine the base output key with the label tweak key
			    const secp256k1_pubkey *tweak_pubkeys[2] = {&base_output_key, &label_tweak_pubkey};
			    secp256k1_pubkey tweaked_output_key;
			    if (secp256k1_ec_pubkey_combine(ctx, &tweaked_output_key, tweak_pubkeys, 2) != 1) {
				    continue;
			    }

			    // Serialize the tweaked output key to compressed format
			    unsigned char tweaked_compressed[33];
			    size_t tweaked_len = 33;
			    if (secp256k1_ec_pubkey_serialize(ctx, tweaked_compressed, &tweaked_len, &tweaked_output_key,
			                                      SECP256K1_EC_COMPRESSED) != 1) {
				    continue;
			    }

			    // Extract first 8 bytes of tweaked x-coordinate as big-endian int64
			    int64_t tweaked_prefix = ExtractBigEndianInt64(tweaked_compressed + 1);

			    // Check if this tweaked x value matches any in the outputs list
			    for (idx_t j = 0; j < outputs_list.length; j++) {
				    idx_t output_idx = outputs_list.offset + j;

				    if (FlatVector::IsNull(outputs_child_vector, output_idx)) {
					    continue;
				    }

				    auto output_int64 = FlatVector::GetData<int64_t>(outputs_child_vector)[output_idx];
				    if (output_int64 == tweaked_prefix) {
					    return true;
				    }
			    }

			    // Try with negated result of the addition
			    secp256k1_pubkey negated_tweaked_key = tweaked_output_key;
			    if (secp256k1_ec_pubkey_negate(ctx, &negated_tweaked_key) != 1) {
				    continue;
			    }

			    // Serialize the negated tweaked key to compressed format
			    unsigned char negated_tweaked_compressed[33];
			    size_t negated_tweaked_len = 33;
			    if (secp256k1_ec_pubkey_serialize(ctx, negated_tweaked_compressed, &negated_tweaked_len,
			                                      &negated_tweaked_key, SECP256K1_EC_COMPRESSED) != 1) {
				    continue;
			    }

			    // Extract first 8 bytes of negated tweaked x-coordinate as big-endian int64
			    int64_t negated_tweaked_prefix = ExtractBigEndianInt64(negated_tweaked_compressed + 1);

			    // Check if this negated tweaked x value matches any in the outputs list
			    for (idx_t j = 0; j < outputs_list.length; j++) {
				    idx_t output_idx = outputs_list.offset + j;

				    if (FlatVector::IsNull(outputs_child_vector, output_idx)) {
					    continue;
				    }

				    auto output_int64 = FlatVector::GetData<int64_t>(outputs_child_vector)[output_idx];
				    if (output_int64 == negated_tweaked_prefix) {
					    return true;
				    }
			    }
		    }

		    return false;
	    });
}

static void LoadInternal(DatabaseInstance &instance) {
	// Register the secp256k1_ec_pubkey_combine function that accepts an array of blobs
	auto secp256k1_ec_pubkey_combine_function =
	    ScalarFunction("secp256k1_ec_pubkey_combine", {LogicalType::LIST(LogicalType::BLOB)}, LogicalType::BLOB,
	                   Secp256k1EcPubkeyCombineScalarFun);
	ExtensionUtil::RegisterFunction(instance, secp256k1_ec_pubkey_combine_function);

	// Register the create_outpoint function
	auto create_outpoint_function = ScalarFunction("create_outpoint", {LogicalType::BLOB, LogicalType::INTEGER},
	                                               LogicalType::BLOB, CreateOutpointScalarFun);
	ExtensionUtil::RegisterFunction(instance, create_outpoint_function);

	// Register the min_outpoint function that accepts an array of blobs
	auto min_outpoint_function =
	    ScalarFunction("min_outpoint", {LogicalType::LIST(LogicalType::BLOB)}, LogicalType::BLOB, MinOutpointScalarFun);
	ExtensionUtil::RegisterFunction(instance, min_outpoint_function);

	// Register the secp256k1_tagged_sha256 function
	auto secp256k1_tagged_sha256_function =
	    ScalarFunction("secp256k1_tagged_sha256", {LogicalType::BLOB, LogicalType::BLOB}, LogicalType::BLOB,
	                   Secp256k1TaggedSha256ScalarFun);
	ExtensionUtil::RegisterFunction(instance, secp256k1_tagged_sha256_function);

	// Register the secp256k1_ec_pubkey_tweak_mul function
	auto secp256k1_ec_pubkey_tweak_mul_function =
	    ScalarFunction("secp256k1_ec_pubkey_tweak_mul", {LogicalType::BLOB, LogicalType::BLOB}, LogicalType::BLOB,
	                   Secp256k1EcPubkeyTweakMulScalarFun);
	ExtensionUtil::RegisterFunction(instance, secp256k1_ec_pubkey_tweak_mul_function);

	// Register the secp256k1_ec_pubkey_create function
	auto secp256k1_ec_pubkey_create_function = ScalarFunction("secp256k1_ec_pubkey_create", {LogicalType::BLOB},
	                                                          LogicalType::BLOB, Secp256k1EcPubkeyCreateScalarFun);
	ExtensionUtil::RegisterFunction(instance, secp256k1_ec_pubkey_create_function);

	// Register the hash prefix to integer function
	auto hash_prefix_to_int_function = ScalarFunction("hash_prefix_to_int", {LogicalType::BLOB, LogicalType::UINTEGER},
	                                                  LogicalType::BIGINT, HashPrefixToIntScalarFun);
	ExtensionUtil::RegisterFunction(instance, hash_prefix_to_int_function);

	// Register the integer to big-endian function
	auto int_to_big_endian_function =
	    ScalarFunction("int_to_big_endian", {LogicalType::INTEGER}, LogicalType::BLOB, IntegerToBigEndianScalarFun);
	ExtensionUtil::RegisterFunction(instance, int_to_big_endian_function);

	// Register the x-only key match function
	auto secp256k1_xonly_key_match_function = ScalarFunction(
	    "secp256k1_xonly_key_match",
	    {LogicalType::LIST(LogicalType::BIGINT), LogicalType::BLOB, LogicalType::LIST(LogicalType::BLOB)},
	    LogicalType::BOOLEAN, Secp256k1XOnlyKeyMatchScalarFun);
	ExtensionUtil::RegisterFunction(instance, secp256k1_xonly_key_match_function);

	// Register the scan_silent_payments function
	auto scan_silent_payments_function =
	    ScalarFunction("scan_silent_payments",
	                   {LogicalType::LIST(LogicalType::BIGINT), LogicalType::LIST(LogicalType::BLOB),
	                    LogicalType::LIST(LogicalType::BLOB)},
	                   LogicalType::BOOLEAN, ScanSilentPaymentsScalarFun);
	ExtensionUtil::RegisterFunction(instance, scan_silent_payments_function);
}

void Secp256k1Extension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}

std::string Secp256k1Extension::Name() {
	return "secp256k1";
}

std::string Secp256k1Extension::Version() const {
#ifdef EXT_VERSION_SECP256K1
	return EXT_VERSION_SECP256K1;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void secp256k1_init(duckdb::DatabaseInstance &db) {
	duckdb::DuckDB db_wrapper(db);
	db_wrapper.LoadExtension<duckdb::Secp256k1Extension>();
}

DUCKDB_EXTENSION_API const char *secp256k1_version() {
	return duckdb::DuckDB::LibraryVersion();
}

// Cleanup function to destroy the secp256k1 context
DUCKDB_EXTENSION_API void secp256k1_cleanup() {
	if (duckdb::secp256k1_ctx) {
		secp256k1_context_destroy(duckdb::secp256k1_ctx);
		duckdb::secp256k1_ctx = nullptr;
	}
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
