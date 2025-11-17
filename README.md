# veritysetup-go

A pure Go implementation of the `veritysetup` toolchain, providing dm-verity functionality without C dependencies.

## Overview

`veritysetup-go` provides:

- `pkg/verity` – High-level API for building and verifying dm-verity hash trees (with or without superblocks)
- `pkg/dm` – Pure Go device-mapper bindings for activating `verity` targets on Linux
- `pkg/utils` – Utilities for block device operations, loop device management, and hash calculations
- `cmd/veritysetup-go` – CLI tool compatible with upstream `veritysetup` commands

## Requirements

- Linux kernel with dm-verity support (CLI usage; library is cross-platform but device activation is Linux-only)
- `dmsetup` and `veritysetup` binaries required only for compatibility tests

## Features

- Format and verify dm-verity images via `VerityCreate` and `VerityVerify` (superblock and legacy layouts)
- Support for SHA1, SHA256, SHA512 hash algorithms with automatic UUID generation
- Pure Go device-mapper ioctl interface for activating, querying, and removing `verity` devices
- Full CLI compatibility: `format`, `verify`, `open`, `close`, `status`, `dump`
- Comprehensive integration tests with upstream `cryptsetup` interoperability checks
- Compatibility tests

## Installation

### CLI Tool

Install latest version:
```bash
go install github.com/ChengyuZhu6/veritysetup-go/cmd/veritysetup-go@latest
```

Build from source:
```bash
git clone https://github.com/ChengyuZhu6/veritysetup-go.git
cd veritysetup-go
make
# Binary will be in bin/veritysetup-go
```

### Library

Add to your Go module:
```bash
go get github.com/ChengyuZhu6/veritysetup-go
```

## Quick Start

### Create and verify a dm-verity image

```bash
# 1. Create a data file (1MB of random data)
dd if=/dev/urandom of=data.img bs=4096 count=256

# 2. Format with dm-verity (creates hash tree)
veritysetup-go format --hash sha256 data.img hash.img

# Output shows root hash, e.g.:
# Root hash: 8f3f2e1d4c5b6a7890abcdef...

# 3. Verify the data
veritysetup-go verify data.img hash.img <root-hash>

# 4. Activate dm-verity device (requires root)
sudo veritysetup-go open data.img my-verity hash.img <root-hash>

# 5. Check device status
sudo veritysetup-go status my-verity

# 6. Access the verified device
sudo dd if=/dev/mapper/my-verity of=/dev/null bs=4096

# 7. Close the device
sudo veritysetup-go close my-verity
```

## Library Usage

### Format data and write superblock

```go
package main

import (
    "log"
    "github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
    "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
)

func main() {
    params := verity.DefaultVerityParams()
    params.HashName = "sha256"
    
    size, err := utils.GetBlockOrFileSize("data.img")
    if err != nil {
        log.Fatal(err)
    }
    params.DataBlocks = uint64(size / int64(params.DataBlockSize))

    rootDigest, err := verity.VerityCreate(&params, "data.img", "hash.img")
    if err != nil {
        log.Fatalf("create verity tree: %v", err)
    }
    log.Printf("root hash: %x", rootDigest)
}
```

### Verify data

```go
verifyParams := verity.DefaultVerityParams()
// VerityVerify automatically reads parameters from superblock when present
if err := verity.VerityVerify(&verifyParams, "data.img", "hash.img", rootDigest); err != nil {
    log.Fatalf("verity verification failed: %v", err)
}
```

For no-superblock layouts, set `verifyParams.NoSuperblock = true` and populate required fields.

## CLI Usage

Build CLI tool:
```bash
make
```

### Available Commands

| Command | Description |
|---------|-------------|
| `format` | Create hash tree and optional superblock |
| `verify` | Validate data against root hash |
| `open` | Activate dm-verity device mapping |
| `close` | Deactivate dm-verity device mapping |
| `status` | Display active device information |
| `dump` | Display on-disk superblock information |

### Command Examples

#### Format with superblock (recommended)
```bash
veritysetup-go format --hash sha256 data.img hash.img
```

#### Format without superblock (legacy mode)
```bash
veritysetup-go format --no-superblock --hash-offset 0 data.img hash.img
```

#### Verify (automatic superblock detection)
```bash
veritysetup-go verify data.img hash.img <root-hash-hex>
```

#### Activate device
```bash
sudo veritysetup-go open data.img my-verity hash.img <root-hash-hex>
```

#### Check device status
```bash
sudo veritysetup-go status my-verity
```

#### Close device
```bash
sudo veritysetup-go close my-verity
```

#### Display superblock information
```bash
veritysetup-go dump hash.img
```

### Common Options

Run `veritysetup-go <command> --help` for detailed options:

- `--hash <algorithm>` - Hash algorithm (sha1, sha256, sha512)
- `--data-block-size <bytes>` - Data block size (512-524288, power of 2)
- `--hash-block-size <bytes>` - Hash block size (512-524288, power of 2)
- `--salt <hex|->` - Salt as hex string or '-' for no salt
- `--uuid <uuid>` - UUID for superblock format
- `--no-superblock` - Use legacy format without superblock
- `--hash-offset <bytes>` - Hash area offset (no-superblock mode)

## Testing

```bash
go test ./...
```

- CLI and device-mapper tests (`*_linux_test.go`) run only on Linux and require root privileges plus `dmsetup` and `veritysetup` binaries
- Compatibility script `tests/verity-compat.sh` provides additional test coverage across multiple hash algorithms and layouts

## Feature Comparison

### Implemented Features

#### Core Commands
- **format** - Create dm-verity hash tree and optional superblock
- **verify** - Validate data against root hash
- **open** - Activate dm-verity device mapping
- **close** - Deactivate dm-verity device mapping
- **status** - Display active device information
- **dump** - Display on-disk superblock information

#### Library Features
- Pure Go device-mapper ioctl bindings
- Pure Go loop device management
- Merkle tree construction and verification
- Superblock read/write operations
- Block device size detection
- Cross-validation with C veritysetup
- Root hash signature verification

#### Hash Algorithms
- SHA1, SHA256 (default), SHA512

#### Format Types
- Format 1 (normal with superblock)
- Format 0 (original Chrome OS, no superblock)

### Missing Features

- FEC (Forward Error Correction) support
- Advanced error handling modes
- Deferred device removal
- BLAKE2, SHA3 hash algorithms
- Parallel hashing for performance

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [dm-verity kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html)
- [veritysetup man page](https://man7.org/linux/man-pages/man8/veritysetup.8.html)