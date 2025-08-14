#pragma once

#include "duckdb.hpp"

namespace duckdb {

class Secp256k1Extension : public Extension {
public:
	void Load(DuckDB &db) override;
	std::string Name() override;
	std::string Version() const override;
};

} // namespace duckdb
