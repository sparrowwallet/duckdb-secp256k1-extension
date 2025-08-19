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
	
	UnaryExecutor::ExecuteWithNulls<list_entry_t, string_t>(
		list_vector, result, args.size(),
		[&](list_entry_t list_data, ValidityMask &mask, idx_t idx) {
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

				// Parse the public key - copy the data locally to avoid pointer issues
				secp256k1_pubkey pubkey;
				unsigned char input_data[33];
				memcpy(input_data, blob_data.GetData(), 33);

				if (secp256k1_ec_pubkey_parse(ctx, &pubkey, input_data, 33) != 1) {
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

			if (secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &combined_pubkey, SECP256K1_EC_COMPRESSED) != 1) {
				// Set result to NULL for this row if serialization failed
				mask.SetInvalid(idx);
				return string_t();
			}

			// Create and return the result blob
			return StringVector::AddStringOrBlob(result, (const char *)output, 33);
		}
	);
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
			unsigned char input_data[32];
			memcpy(input_data, blob_data.GetData(), 32);
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
		}
	);
}

// Function to find the lexicographically smallest 36-byte blob
inline void MinOutpointScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	// The function takes a single LIST argument containing BLOB elements (each 36 bytes for outpoints)
	D_ASSERT(args.ColumnCount() == 1);

	auto &list_vector = args.data[0];
	
	UnaryExecutor::ExecuteWithNulls<list_entry_t, string_t>(
		list_vector, result, args.size(),
		[&](list_entry_t list_data, ValidityMask &mask, idx_t idx) {
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
		}
	);
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
			int result_code = secp256k1_tagged_sha256(ctx, hash32, (const unsigned char *)tag_str.c_str(), tag_str.size(),
			                                          (const unsigned char *)msg_str.c_str(), msg_str.size());

			if (result_code != 1) {
				// Set result to NULL if hashing failed (though this should always succeed)
				mask.SetInvalid(idx);
				return string_t();
			}

			// Create and return the result blob
			return StringVector::AddStringOrBlob(result, (const char *)hash32, 32);
		}
	);
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

			// Copy input data to safe local buffers
			unsigned char pubkey_input[33];
			unsigned char tweak32[32];
			memcpy(pubkey_input, pubkey_data.GetData(), 33);
			memcpy(tweak32, tweak_data.GetData(), 32);

			// Parse the public key
			secp256k1_pubkey pubkey;
			if (secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_input, 33) != 1) {
				mask.SetInvalid(idx);
				return string_t();
			}

			// Apply the scalar tweak
			if (secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, tweak32) != 1) {
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
		}
	);
}

// Function to create a public key from a secret key using secp256k1_ec_pubkey_create
inline void Secp256k1EcPubkeyCreateScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 1);

	// Get the secp256k1 context
	secp256k1_context *ctx = GetSecp256k1Context();

	UnaryExecutor::ExecuteWithNulls<string_t, string_t>(
		args.data[0], result, args.size(),
		[&](string_t seckey_data, ValidityMask &mask, idx_t idx) {
			// Validate that the secret key is exactly 32 bytes
			if (seckey_data.GetSize() != 32) {
				mask.SetInvalid(idx);
				return string_t();
			}

			// Copy input data to safe local buffer
			unsigned char seckey32[32];
			memcpy(seckey32, seckey_data.GetData(), 32);

			// Create the public key
			secp256k1_pubkey pubkey;
			if (secp256k1_ec_pubkey_create(ctx, &pubkey, seckey32) != 1) {
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
		}
	);
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

			// Copy input data to safe local buffer starting from offset
			unsigned char input_data[8];
			memcpy(input_data, (const char*)blob_data.GetData() + offset, 8);

			// Convert to bigint (big-endian, most significant byte first)
			// Take 8 bytes starting from the offset
			int64_t result_value = 0;
			for (int j = 0; j < 8; j++) {
				result_value = (result_value << 8) | input_data[j];
			}

			return result_value;
		}
	);
}

// Function to convert an integer to a 4-byte blob in big-endian format (MSB first)
inline void IntegerToBigEndianScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 1);

	UnaryExecutor::Execute<int32_t, string_t>(
		args.data[0], result, args.size(),
		[&](int32_t int_value) {
			// Create output buffer (4 bytes)
			unsigned char output[4];

			// Store the integer in big-endian format (most significant byte first)
			output[0] = (unsigned char)((int_value >> 24) & 0xFF); // MSB
			output[1] = (unsigned char)((int_value >> 16) & 0xFF);
			output[2] = (unsigned char)((int_value >> 8) & 0xFF);
			output[3] = (unsigned char)(int_value & 0xFF); // LSB

			// Create and return the result blob
			return StringVector::AddStringOrBlob(result, (const char *)output, 4);
		}
	);
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
	    ScalarFunction("hash_prefix_to_int", {LogicalType::BLOB, LogicalType::UINTEGER}, LogicalType::BIGINT, HashPrefixToIntScalarFun);
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
