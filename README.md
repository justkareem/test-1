# Vanity Keypair Generator

A *blazingly fast* ed25519 keypair generator for Solana vanity addresses with GPU acceleration support.

## What

This tool generates **actual ed25519 keypairs** (not CreateAccountWithSeed addresses) that produce vanity Solana addresses. The generated private keys can be directly imported into wallets like Phantom, Solflare, or any other Solana wallet.

## Features

- **Direct Keypair Generation**: Generates real ed25519 keypairs, not derived addresses
- **Wallet Compatible**: Private keys work directly in Phantom, Solflare, and other wallets
- **GPU Acceleration**: Massive performance boost with CUDA support
- **CPU Fallback**: Works without GPU using multi-threaded CPU processing
- **Prefix & Suffix Matching**: Find addresses that start and/or end with specific strings
- **Case Insensitive**: Optional case-insensitive matching for broader results

## Installation

### CPU-only Build
```bash
cargo build --release
cargo install --path .
```

### GPU-accelerated Build (requires NVIDIA GPU with CUDA)
```bash
cargo build --release --features=gpu
cargo install --path . --features=gpu
```

## Usage

### Basic Command Structure
```bash
vanity-keypair [OPTIONS]
```

### Options
```
--prefix <PREFIX>          Target prefix for the address (e.g., "kare", "dead")
--suffix <SUFFIX>          Target suffix for the address (e.g., "beef", "cafe")
--case-insensitive         Enable case-insensitive matching
--logfile <LOGFILE>        Optional log file for output
--num-cpus <NUM_CPUS>      Number of CPU threads [default: auto-detect]
--num-gpus <NUM_GPUS>      Number of GPUs to use (GPU build only) [default: 1]
-h, --help                 Print help information
```

### Examples

#### Find address starting with "kare"
```bash
vanity-keypair --prefix kare
```

#### Find address ending with "dead" (case insensitive)
```bash
vanity-keypair --suffix dead --case-insensitive
```

#### Use GPU acceleration
```bash
vanity-keypair --prefix cafe --num-gpus 1
```

#### Use 8 CPU threads
```bash
vanity-keypair --prefix abc --num-cpus 8
```

#### Combine prefix and suffix
```bash
vanity-keypair --prefix kare --suffix dead
```

## Output Format

When a vanity address is found, the tool outputs:

```
[2025-09-08 13:14:10 INFO] kareXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX found in 0.322 seconds
[2025-09-08 13:14:10 INFO] Public Key: kareXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[2025-09-08 13:14:10 INFO] Private Key (for Phantom/wallet import): [Base58 encoded private key]
[2025-09-08 13:14:10 INFO] Private Key Array: [32-byte array format]
```

## Wallet Import

### Phantom Wallet
1. Open Phantom
2. Go to Settings → Private Key Import
3. Paste the "Private Key (for Phantom/wallet import)" value
4. Your vanity address will be imported

### Other Wallets
Most Solana wallets accept the Base58-encoded private key format provided in the output.

## Performance

- **CPU Mode**: Typically 50,000-200,000 attempts per second per core
- **GPU Mode**: Up to 1+ billion attempts per second (depending on GPU)

Higher character count prefixes/suffixes will take exponentially longer to find.

## Requirements

### CPU Build
- Rust 1.70+
- Standard build tools

### GPU Build
- NVIDIA GPU with CUDA compute capability 8.9+
- CUDA Toolkit 11.0+
- NVIDIA drivers

## Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd vanity-keypair

# CPU-only build
cargo build --release

# GPU-accelerated build
cargo build --release --features=gpu
```

## License

MIT OR Apache-2.0

## Acknowledgments

- SHA256 implementation from [cuda-hashing-algos](https://github.com/mochimodev/cuda-hashing-algos) (public domain)
- Base58 encoding adapted from Firedancer (Apache-2.0)
- Ed25519 support via [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)

## Security Note

This tool generates cryptographically secure keypairs suitable for production use. However, always verify the security of any tool before using it with valuable assets.