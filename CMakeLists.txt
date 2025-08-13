cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME secp256k1)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)
include_directories(secp256k1/include)

# Include secp256k1 source directly to avoid export issues
set(EXTENSION_SOURCES 
    src/secp256k1_extension.cpp
    secp256k1/src/secp256k1.c
    secp256k1/src/precomputed_ecmult.c
    secp256k1/src/precomputed_ecmult_gen.c
)

# Add necessary preprocessor definitions for secp256k1
add_definitions(-DECMULT_WINDOW_SIZE=15)
add_definitions(-DECMULT_GEN_PRECISION_BITS=4)
add_definitions(-DUSE_FIELD_10X26)
add_definitions(-DUSE_SCALAR_8X32)
add_definitions(-DENABLE_MODULE_ECDH)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
