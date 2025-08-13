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
static secp256k1_context* secp256k1_ctx = nullptr;

// Helper function to initialize secp256k1 context
static secp256k1_context* GetSecp256k1Context() {
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
	
	// The function takes a variable number of BLOB arguments (each 33 bytes for compressed pubkeys)
	D_ASSERT(args.ColumnCount() >= 1);
	
	// Get number of rows to process
	idx_t count = args.size();
	
	// Process each row
	for (idx_t i = 0; i < count; i++) {
		std::vector<secp256k1_pubkey> parsed_pubkeys;
		std::vector<const secp256k1_pubkey*> pubkey_ptrs;
		
		bool all_valid = true;
		
		// Parse all input public keys for this row
		for (idx_t col = 0; col < args.ColumnCount(); col++) {
			auto &input_vector = args.data[col];
			
			// Check if this column value is NULL
			if (FlatVector::IsNull(input_vector, i)) {
				all_valid = false;
				break;
			}
			
			// Get the blob data
			auto blob_data = FlatVector::GetData<string_t>(input_vector)[i];
			
			// Validate that the blob is exactly 33 bytes (compressed pubkey format)
			if (blob_data.GetSize() != 33) {
				all_valid = false;
				break;
			}
			
			// Parse the public key
			secp256k1_pubkey pubkey;
			const unsigned char *input_data = reinterpret_cast<const unsigned char*>(blob_data.GetDataUnsafe());
			
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
		for (const auto& pk : parsed_pubkeys) {
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
		string_t result_blob = StringVector::AddStringOrBlob(result, (const char*)output, 33);
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
		
		// Copy the 32-byte blob
		memcpy(output, blob_data.GetDataUnsafe(), 32);
		
		// Append the 4-byte integer in little-endian format
		output[32] = (unsigned char)(int_value & 0xFF);
		output[33] = (unsigned char)((int_value >> 8) & 0xFF);
		output[34] = (unsigned char)((int_value >> 16) & 0xFF);
		output[35] = (unsigned char)((int_value >> 24) & 0xFF);
		
		// Create the result blob
		string_t result_blob = StringVector::AddStringOrBlob(result, (const char*)output, 36);
		FlatVector::GetData<string_t>(result)[i] = result_blob;
	}
}

// Function to find the lexicographically smallest 36-byte blob
inline void MinOutpointScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	// Get number of rows to process
	idx_t count = args.size();
	
	// Process each row
	for (idx_t i = 0; i < count; i++) {
		string_t min_blob;
		bool found_valid = false;
		
		// Check all input arguments for this row
		for (idx_t col = 0; col < args.ColumnCount(); col++) {
			auto &input_vector = args.data[col];
			
			// Check if this column value is NULL
			if (FlatVector::IsNull(input_vector, i)) {
				continue;
			}
			
			// Get the blob data
			auto blob_data = FlatVector::GetData<string_t>(input_vector)[i];
			
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
			string_t result_blob = StringVector::AddStringOrBlob(result, 
				(const char*)min_blob.GetDataUnsafe(), 36);
			FlatVector::GetData<string_t>(result)[i] = result_blob;
		}
	}
}

static void LoadInternal(DatabaseInstance &instance) {
	// Register the secp256k1_ec_pubkey_combine function that accepts variable arguments
	ScalarFunctionSet secp256k1_ec_pubkey_combine_function_set("secp256k1_ec_pubkey_combine");
	
	// Add overloads for different numbers of arguments (2-10 public keys)
	for (idx_t num_args = 2; num_args <= 10; num_args++) {
		vector<LogicalType> arg_types;
		for (idx_t i = 0; i < num_args; i++) {
			arg_types.push_back(LogicalType::BLOB);
		}
		
		secp256k1_ec_pubkey_combine_function_set.AddFunction(ScalarFunction(
			arg_types, LogicalType::BLOB, Secp256k1EcPubkeyCombineScalarFun
		));
	}
	
	ExtensionUtil::RegisterFunction(instance, secp256k1_ec_pubkey_combine_function_set);
	
	// Register the create_outpoint function
	auto create_outpoint_function = ScalarFunction("create_outpoint", 
		{LogicalType::BLOB, LogicalType::INTEGER}, LogicalType::BLOB, CreateOutpointScalarFun);
	ExtensionUtil::RegisterFunction(instance, create_outpoint_function);
	
	// Register the min_outpoint function that accepts variable arguments
	ScalarFunctionSet min_outpoint_function_set("min_outpoint");
	
	// Add overloads for different numbers of arguments (2-10 outpoints)
	for (idx_t num_args = 2; num_args <= 10; num_args++) {
		vector<LogicalType> arg_types;
		for (idx_t i = 0; i < num_args; i++) {
			arg_types.push_back(LogicalType::BLOB);
		}
		
		min_outpoint_function_set.AddFunction(ScalarFunction(
			arg_types, LogicalType::BLOB, MinOutpointScalarFun
		));
	}
	
	ExtensionUtil::RegisterFunction(instance, min_outpoint_function_set);
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