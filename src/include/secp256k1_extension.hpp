#pragma once

#include "duckdb.hpp"

namespace duckdb {

class Secp256k1Extension : public Extension {
public:
	~Secp256k1Extension() override;
	void Load(ExtensionLoader &loader) override;
	std::string Name() override;
	std::string Version() const override;
};

} // namespace duckdb
