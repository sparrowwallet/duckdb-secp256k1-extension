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

	// Get number of rows to process
	idx_t count = args.size();

	// Process each row
	for (idx_t i = 0; i < count; i++) {
		// Check if the list is NULL
		if (FlatVector::IsNull(list_vector, i)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the list data for this row
		auto list_data = FlatVector::GetData<list_entry_t>(list_vector)[i];

		// Get the child vector (contains the actual BLOB elements)
		auto &child_vector = ListVector::GetEntry(list_vector);

		std::vector<secp256k1_pubkey> parsed_pubkeys;
		std::vector<const secp256k1_pubkey *> pubkey_ptrs;

		bool all_valid = true;

		// Check if list is empty
		if (list_data.length == 0) {
			FlatVector::SetNull(result, i, true);
			continue;
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
			const unsigned char *input_data = reinterpret_cast<const unsigned char *>(blob_data.GetDataUnsafe());

			if (secp256k1_ec_pubkey_parse(ctx, &pubkey, input_data, 33) != 1) {
				all_valid = false;
				break;
			}

			parsed_pubkeys.push_back(pubkey);
		}

		if (!all_valid || parsed_pubkeys.empty()) {
			// Set result to NULL for this row
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Create array of pointers for secp256k1_ec_pubkey_combine
		for (const auto &pk : parsed_pubkeys) {
			pubkey_ptrs.push_back(&pk);
		}

		// Combine the public keys
		secp256k1_pubkey combined_pubkey;
		if (secp256k1_ec_pubkey_combine(ctx, &combined_pubkey, pubkey_ptrs.data(), pubkey_ptrs.size()) != 1) {
			// Set result to NULL for this row if combination failed
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Serialize the combined public key back to compressed format (33 bytes)
		unsigned char output[33];
		size_t output_len = 33;

		if (secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &combined_pubkey, SECP256K1_EC_COMPRESSED) != 1) {
			// Set result to NULL for this row if serialization failed
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Create the result blob
		string_t result_blob = StringVector::AddStringOrBlob(result, (const char *)output, 33);
		FlatVector::GetData<string_t>(result)[i] = result_blob;
	}
}

// Function to concatenate a 32-byte blob with a 4-byte integer in little-endian format
inline void CreateOutpointScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 2);

	auto &blob_vector = args.data[0];
	auto &int_vector = args.data[1];

	// Get number of rows to process
	idx_t count = args.size();

	// Process each row
	for (idx_t i = 0; i < count; i++) {
		// Check if either input is NULL
		if (FlatVector::IsNull(blob_vector, i) || FlatVector::IsNull(int_vector, i)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the blob data
		auto blob_data = FlatVector::GetData<string_t>(blob_vector)[i];

		// Validate that the blob is exactly 32 bytes
		if (blob_data.GetSize() != 32) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the integer value
		auto int_value = FlatVector::GetData<int32_t>(int_vector)[i];

		// Create output buffer (32 bytes + 4 bytes = 36 bytes)
		unsigned char output[36];

		// Copy the 32-byte blob in reverse order (big-endian to little-endian)
		const unsigned char *input_data = reinterpret_cast<const unsigned char *>(blob_data.GetDataUnsafe());
		for (int j = 0; j < 32; j++) {
			output[j] = input_data[31 - j];
		}

		// Append the 4-byte integer in little-endian format
		output[32] = (unsigned char)(int_value & 0xFF);
		output[33] = (unsigned char)((int_value >> 8) & 0xFF);
		output[34] = (unsigned char)((int_value >> 16) & 0xFF);
		output[35] = (unsigned char)((int_value >> 24) & 0xFF);

		// Create the result blob
		string_t result_blob = StringVector::AddStringOrBlob(result, (const char *)output, 36);
		FlatVector::GetData<string_t>(result)[i] = result_blob;
	}
}

// Function to find the lexicographically smallest 36-byte blob
inline void MinOutpointScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	// The function takes a single LIST argument containing BLOB elements (each 36 bytes for outpoints)
	D_ASSERT(args.ColumnCount() == 1);

	auto &list_vector = args.data[0];

	// Get number of rows to process
	idx_t count = args.size();

	// Process each row
	for (idx_t i = 0; i < count; i++) {
		// Check if the list is NULL
		if (FlatVector::IsNull(list_vector, i)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the list data for this row
		auto list_data = FlatVector::GetData<list_entry_t>(list_vector)[i];

		// Get the child vector (contains the actual BLOB elements)
		auto &child_vector = ListVector::GetEntry(list_vector);

		string_t min_blob;
		bool found_valid = false;

		// Check if list is empty
		if (list_data.length == 0) {
			FlatVector::SetNull(result, i, true);
			continue;
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
				if (memcmp(blob_data.GetDataUnsafe(), min_blob.GetDataUnsafe(), 36) < 0) {
					min_blob = blob_data;
				}
			}
		}

		if (!found_valid) {
			// Set result to NULL if no valid 36-byte blobs found
			FlatVector::SetNull(result, i, true);
		} else {
			// Create the result blob by copying the minimum blob
			string_t result_blob = StringVector::AddStringOrBlob(result, (const char *)min_blob.GetDataUnsafe(), 36);
			FlatVector::GetData<string_t>(result)[i] = result_blob;
		}
	}
}

// Function to compute secp256k1 tagged SHA256 hash
inline void Secp256k1TaggedSha256ScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 2);

	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	auto &tag_vector = args.data[0];
	auto &msg_vector = args.data[1];

	// Get number of rows to process
	idx_t count = args.size();

	// Process each row
	for (idx_t i = 0; i < count; i++) {
		// Check if either input is NULL
		if (FlatVector::IsNull(tag_vector, i) || FlatVector::IsNull(msg_vector, i)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the tag data
		auto tag_data = FlatVector::GetData<string_t>(tag_vector)[i];
		// Get the message data
		auto msg_data = FlatVector::GetData<string_t>(msg_vector)[i];

		// Create output buffer for 32-byte hash
		unsigned char hash32[32];

		// Call secp256k1_tagged_sha256
		int result_code =
		    secp256k1_tagged_sha256(ctx, hash32, (const unsigned char *)tag_data.GetDataUnsafe(), tag_data.GetSize(),
		                            (const unsigned char *)msg_data.GetDataUnsafe(), msg_data.GetSize());

		if (result_code != 1) {
			// Set result to NULL if hashing failed (though this should always succeed)
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Create the result blob
		string_t result_blob = StringVector::AddStringOrBlob(result, (const char *)hash32, 32);
		FlatVector::GetData<string_t>(result)[i] = result_blob;
	}
}

// Function to tweak a public key by scalar multiplication
inline void Secp256k1EcPubkeyTweakMulScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 2);

	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	auto &pubkey_vector = args.data[0];
	auto &tweak_vector = args.data[1];

	// Get number of rows to process
	idx_t count = args.size();

	// Process each row
	for (idx_t i = 0; i < count; i++) {
		// Check if either input is NULL
		if (FlatVector::IsNull(pubkey_vector, i) || FlatVector::IsNull(tweak_vector, i)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the public key data
		auto pubkey_data = FlatVector::GetData<string_t>(pubkey_vector)[i];
		// Get the tweak data
		auto tweak_data = FlatVector::GetData<string_t>(tweak_vector)[i];

		// Validate that the public key is exactly 33 bytes (compressed format)
		if (pubkey_data.GetSize() != 33) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Validate that the tweak is exactly 32 bytes
		if (tweak_data.GetSize() != 32) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Parse the public key
		secp256k1_pubkey pubkey;
		const unsigned char *pubkey_input = reinterpret_cast<const unsigned char *>(pubkey_data.GetDataUnsafe());

		if (secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_input, 33) != 1) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Apply the scalar tweak
		const unsigned char *tweak32 = reinterpret_cast<const unsigned char *>(tweak_data.GetDataUnsafe());

		if (secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, tweak32) != 1) {
			// Tweak failed (invalid tweak or resulting point at infinity)
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Serialize the tweaked public key back to compressed format (33 bytes)
		unsigned char output[33];
		size_t output_len = 33;

		if (secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &pubkey, SECP256K1_EC_COMPRESSED) != 1) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Create the result blob
		string_t result_blob = StringVector::AddStringOrBlob(result, (const char *)output, 33);
		FlatVector::GetData<string_t>(result)[i] = result_blob;
	}
}

// Function to create a public key from a secret key using secp256k1_ec_pubkey_create
inline void Secp256k1EcPubkeyCreateScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 1);

	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	auto &seckey_vector = args.data[0];

	// Get number of rows to process
	idx_t count = args.size();

	// Process each row
	for (idx_t i = 0; i < count; i++) {
		// Check if input is NULL
		if (FlatVector::IsNull(seckey_vector, i)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the secret key data
		auto seckey_data = FlatVector::GetData<string_t>(seckey_vector)[i];

		// Validate that the secret key is exactly 32 bytes
		if (seckey_data.GetSize() != 32) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Create the public key
		secp256k1_pubkey pubkey;
		const unsigned char *seckey32 = reinterpret_cast<const unsigned char *>(seckey_data.GetDataUnsafe());

		if (secp256k1_ec_pubkey_create(ctx, &pubkey, seckey32) != 1) {
			// Secret key is invalid (zero, out of range, etc.)
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Serialize the public key to compressed format (33 bytes)
		unsigned char output[33];
		size_t output_len = 33;

		if (secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &pubkey, SECP256K1_EC_COMPRESSED) != 1) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Create the result blob
		string_t result_blob = StringVector::AddStringOrBlob(result, (const char *)output, 33);
		FlatVector::GetData<string_t>(result)[i] = result_blob;
	}
}

// Function to convert a 32-byte blob to a ubigint with most significant byte first
inline void HashPrefixToIntScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 1);

	auto &blob_vector = args.data[0];

	// Get number of rows to process
	idx_t count = args.size();

	// Process each row
	for (idx_t i = 0; i < count; i++) {
		// Check if input is NULL
		if (FlatVector::IsNull(blob_vector, i)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the blob data
		auto blob_data = FlatVector::GetData<string_t>(blob_vector)[i];

		// Validate that the blob is exactly 32 bytes
		if (blob_data.GetSize() != 32) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the input data as unsigned char array
		const unsigned char *input_data = reinterpret_cast<const unsigned char *>(blob_data.GetDataUnsafe());

		// Convert to bigint (big-endian, most significant byte first)
		// Take the first 8 bytes of the hash as the most significant bytes
		int64_t result_value = 0;
		for (int j = 0; j < 8; j++) {
			result_value = (result_value << 8) | input_data[j];
		}

		// Set the result
		FlatVector::GetData<int64_t>(result)[i] = result_value;
	}
}

// Function to convert an integer to a 4-byte blob in big-endian format (MSB first)
inline void IntegerToBigEndianScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 1);

	auto &int_vector = args.data[0];

	// Get number of rows to process
	idx_t count = args.size();

	// Process each row
	for (idx_t i = 0; i < count; i++) {
		// Check if input is NULL
		if (FlatVector::IsNull(int_vector, i)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		// Get the integer value
		auto int_value = FlatVector::GetData<int32_t>(int_vector)[i];

		// Create output buffer (4 bytes)
		unsigned char output[4];

		// Store the integer in big-endian format (most significant byte first)
		output[0] = (unsigned char)((int_value >> 24) & 0xFF); // MSB
		output[1] = (unsigned char)((int_value >> 16) & 0xFF);
		output[2] = (unsigned char)((int_value >> 8) & 0xFF);
		output[3] = (unsigned char)(int_value & 0xFF); // LSB

		// Create the result blob
		string_t result_blob = StringVector::AddStringOrBlob(result, (const char *)output, 4);
		FlatVector::GetData<string_t>(result)[i] = result_blob;
	}
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
	auto hash_prefix_to_int_function =
	    ScalarFunction("hash_prefix_to_int", {LogicalType::BLOB}, LogicalType::BIGINT, HashPrefixToIntScalarFun);
	ExtensionUtil::RegisterFunction(instance, hash_prefix_to_int_function);

	// Register the integer to big-endian function
	auto int_to_big_endian_function =
	    ScalarFunction("int_to_big_endian", {LogicalType::INTEGER}, LogicalType::BLOB, IntegerToBigEndianScalarFun);
	ExtensionUtil::RegisterFunction(instance, int_to_big_endian_function);
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
