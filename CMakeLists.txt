cmake_minimum_required(VERSION 3.22)
project(bbf LANGUAGES CXX)

# Set C++ standard to C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specify output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Set optimization flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mtune=native -pthread")

# Find pkg-config
find_package(PkgConfig REQUIRED)

# Find Boost libraries
find_package(Boost REQUIRED COMPONENTS system)
include_directories(${Boost_INCLUDE_DIRS})


# List of source files for each executable
set(EXECUTABLES
        deterministic_wallet
        deterministic_wallet_v2
)

# Create executables
foreach(EXE_NAME ${EXECUTABLES})
    add_executable(${EXE_NAME} src/${EXE_NAME}.cpp)
endforeach()

# Define libraries to link with
set(LIBBITCOIN_LIBS
        secp256k1
        ssl
        crypto
)

# Link libraries to relevant executables
foreach(EXE_NAME ${EXECUTABLES})
    target_link_libraries(${EXE_NAME} PRIVATE ${LIBBITCOIN_LIBS})
endforeach()

# Print configuration summary
message(STATUS "Output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
