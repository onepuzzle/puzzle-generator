# Bitcoin Puzzle Refactor

This project provides a C++ implementation to generate and verify the Bitcoin Puzzle sequences originally created by saatoshi_rising. It includes deterministic key derivation, bit‑masking, address and WIF generation, and range percentage calculation.

## Two Versions of the Bitcoin Puzzle Generator

I’m offering two slightly different C++ scripts that let you reproduce the famous Bitcoin Puzzle by **saatoshi\_rising**. While both programs perform the same core tasks—deterministically generating private keys, applying bitwise masks, computing the corresponding P2PKH addresses and WIFs, and showing progress through the keyspace—they differ in style, modularity, and output details:

**“Historical” Monolith Variant**

* **Single file, minimal boilerplate.**
* Direct OpenSSL and HMAC calls inside `main()`.
* Output: Index, PrivateKey (hex), Address, WIF, Status (MATCH/FAIL).
* **Why?** As close as possible to saatoshi\_rising’s original script, so you can follow the unadulterated approach step by step.

### Which version most closely matches saatoshi\_rising’s original script?

The **monolith variant**—with its linear, unabstracted flow and simple 4-byte HMAC index—is exactly what saatoshi\_rising likely used back in 2015/2017. It avoids any extra helper functions or extensions added later. If you want the pure Puzzle experience or to recreate the original Puzzle transactions exactly, this is the version to choose.

> **Fun Fact:** If saatoshi\_rising sees this script, he’ll be amazed at how many ways you can structure the same algorithm—and a little nervous, too, since now anyone can scan all the puzzles in seconds (or maybe he used an entirely different method to generate the wallets)…

## Prerequisites

Ensure you have the following tools and libraries installed on your system:

* **Build tools**:

    * `build-essential` (gcc, g++, make)
    * `cmake` (>= 3.22)
    * `pkg-config`

* **Libraries**:

    * `libssl-dev` (OpenSSL: BN, EC, SHA, HMAC, RIPEMD-160)
    * `libboost-all-dev` (Boost)
    * `libsecp256k1-dev` (secp256k1 elliptic curve)

On Debian/Ubuntu, install essentials with:

```bash
sudo apt update
sudo apt install -y \
  build-essential cmake pkg-config ninja-build gdb \
  libssl-dev libboost-all-dev libsecp256k1-dev
```

## Project Structure

```
/ (root)
├── CMakeLists.txt          # Top-level CMake configuration
├── src/
│   ├── deterministic_wallet.cpp     # Main generator (v1)
│   └── deterministic_wallet_v2.cpp  # Refactored version
├── puzzles.cpp             # Definition of the Puzzle array
└── README.md               # This file
```

## Build Instructions

1. **Clone the repository**:

   ```bash
   git clone https://github.com/onepuzzle/puzzle-generator
   cd puzzle-generator
   ```

2. **Create a build directory**:

   ```bash
   mkdir -p build && cd build
   ```

3. **Configure with CMake:

   ```bash
   cmake ..
   ```

4. **Compile**:

   ```bash
   cmake --build .
   ```

5. **Binaries** will be placed in `build/bin/`.

## Usage

```bash
# Basic usage: generate first N puzzles
./build/bin/deterministic_wallet <count> <masterSeed> [hideNonMatches=true]

# Example:
./build/bin/deterministic_wallet 160 mySecretSeed
./build/bin/deterministic_wallet 160 "maybe with space"
```

* `<count>`: Number of puzzle outputs (1–256)
* `<masterSeed>`: Either a 64‑hex seed or a passphrase (SHA256 hashed internally)
* `[hideNonMatches]`: Optional flag (`true`) to omit unsolved puzzles

For the refactored version:

```bash
./build/bin/deterministic_wallet_v2 160 abcd1234ef...(private key hex)
./build/bin/deterministic_wallet_v2 160 mySecretSeed (or seed)
```

## Donations

If you find this tool helpful, your support is greatly appreciated! 💖

* **Bitcoin**: [bc1qh33frsqg06pafhcaj8kzljau04shwwp3ujwl6h](https://www.blockchain.com/btc/address/bc1qh33frsqg06pafhcaj8kzljau04shwwp3ujwl6h)

## License

This project is released under the MIT License.
