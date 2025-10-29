# veritysetup-go

A pure Go implementation of veritysetup tool, providing dm-verity functionality without system dependencies.

## Overview

This project aims to provide a pure Go alternative to the `veritysetup` tool, enabling Go applications to perform dm-verity operations without requiring the system to have veritysetup installed. It's fully compatible with the Linux kernel's device-mapper verity target and can seamlessly replace veritysetup tool functionality in Go projects.

The main motivation is to eliminate the system dependency on veritysetup when Go projects need to work with dm-verity, making the applications more portable and easier to deploy.

## Features

Currently implemented:
- Hash tree creation and verification
- Support for multiple hash algorithms (SHA1, SHA256, SHA512)
- Compatible with Linux kernel's dm-verity format
- Support for multiple hash tree levels
- Data corruption detection
- Configurable block sizes
- Flexible salt configurations
- User-space verifier API for full/partial verification

## Installation

```bash
go get github.com/ChengyuZhu6/veritysetup-go
```

## Usage

This library can be used as a drop-in replacement for veritysetup in Go projects:

### Creating a Hash Tree

```go
params := &verity.VerityParams{
    HashName:      "sha256", // supports "sha1", "sha256", "sha512"
    DataBlockSize: 4096,
    HashBlockSize: 4096,
    DataBlocks:    uint64(fileSize / 4096), // number of data blocks
    HashType:      1,
    Salt:          make([]byte, 32),
    SaltSize:      32,
}

vh := verity.NewVerityHash(params, dataPath, hashPath, nil)
if err := vh.Create(); err != nil {
    log.Fatalf("Failed to create hash tree: %v", err)
}

// The root hash is now available via vh.RootHash()
```

### Verifying Data

```go
vh := verity.NewVerityHash(params, dataPath, hashPath, root)
if err := vh.Verify(); err != nil {
    log.Fatalf("Verification failed: %v", err)
}
```

### Using the Verifier API

```go
// Construct a verifier with the expected root digest
verifier, err := verity.NewVerifier(params, dataPath, hashPath, root, verity.VerifyAlways)
if err != nil {
    log.Fatalf("NewVerifier: %v", err)
}
defer verifier.Close()

// Verify the entire data file
if err := verifier.VerifyAll(); err != nil {
    log.Fatalf("VerifyAll failed: %v", err)
}

// Or verify a specific byte range (offset, length)
if err := verifier.VerifyRange(0, 1<<20); err != nil { // first 1 MiB
    log.Fatalf("VerifyRange failed: %v", err)
}
```

Notes:
- When using superblock mode (default), the library writes and validates the superblock automatically and places the hash area after it. You typically do not need to set `HashAreaOffset` manually.
- For no-superblock mode, set `NoSuperblock = true`. Ensure `HashAreaOffset` is appropriate for your layout (often `0`).

### CLI

The CLI's commands, flags, and output format align with `veritysetup` (only the binary name differs), so usage is consistent and it can serve as a drop-in alternative.

Build the CLI with Makefile:

```bash
make
```

Format command usage (subset aligning with veritysetup):

```bash
veritysetup-go format [options] <data_path> <hash_path>

Options:
  --hash <sha1|sha256|sha512>        Hash algorithm (default sha256)
  --format <0|1>                     Format type (1 - normal, 0 - original Chrome OS)
  --data-block-size <bytes>          Data block size (default 4096)
  --hash-block-size <bytes>          Hash block size (default 4096)
  --salt <hex>                       Salt as hex (optional)
  --uuid <uuid>                      UUID (e.g. 123e4567-e89b-12d3-a456-426614174000)
  --data-blocks <n>                  Data blocks (override file size)
  --no-superblock                    Do not write superblock
  --hash-offset <bytes>              Hash area offset (when --no-superblock)
```

Example:

```bash
veritysetup-go format \
  --hash sha256 \
  --format 1 \
  --no-superblock \
  --data-block-size 4096 \
  --hash-block-size 4096 \
  --salt 0000000000000000000000000000000000000000000000000000000000000000 \
  --uuid 00000000-0000-0000-0000-000000000000 \
  "$DATA" verity.file
```

Sample output:

```
VERITY header information for verity.file
UUID:                   
Hash type:              1
Data blocks:            256
Data block size:        4096
Hash blocks:            3
Hash block size:        4096
Hash algorithm:         sha256
Salt:                   0000000000000000000000000000000000000000000000000000000000000000
Root hash:              5eafa40996106436497cbe4cae0bf07e2e32a4d415d3013f908450d410f76289
Hash device size:       12288 [bytes]
```

## Project Status

This is an initial implementation focusing on core functionality. The API may change as we add more features.

### Planned Features

1. Command Line Interface
   - Complete veritysetup command line interface replacement
   - Drop-in replacement for all veritysetup commands

2. Additional Hash Algorithms
   - Support for Blake2b
   - Support for other cryptographic hash functions
   - Pluggable hash algorithm interface

3. Performance Optimizations
   - Parallel hash computation
   - Memory usage optimizations
   - Streaming support for large files
   - Buffer pooling for better memory efficiency

4. Additional Features
   - FEC (Forward Error Correction) support
   - Integration with Linux device-mapper
   - Support for all veritysetup options and configurations
   - Automatic block size optimization

5. Documentation and Tools
   - Detailed API documentation
   - More usage examples
   - Performance benchmarks
   - Migration guide from veritysetup
   - Debugging and analysis tools

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [dm-verity kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html)
- [veritysetup man page](https://man7.org/linux/man-pages/man8/veritysetup.8.html)