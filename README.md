# veritysetup-go

A pure Go implementation of veritysetup tool, providing dm-verity functionality without system dependencies.

## Overview

This project aims to provide a pure Go alternative to the `veritysetup` tool, enabling Go applications to perform dm-verity operations without requiring the system to have veritysetup installed. It's fully compatible with the Linux kernel's device-mapper verity target and can seamlessly replace veritysetup tool functionality in Go projects.

The main motivation is to eliminate the system dependency on veritysetup when Go projects need to work with dm-verity, making the applications more portable and easier to deploy.

## Features

Currently implemented:
- Hash tree creation and verification
- Support for SHA256 hash algorithm
- Compatible with Linux kernel's dm-verity format
- Support for multiple hash tree levels
- Data corruption detection

## Installation

```
go get github.com/ChengyuZhu6/veritysetup-go
```

## Usage

This library can be used as a drop-in replacement for veritysetup in Go projects:

### Creating a Hash Tree

```
params := &verity.VerityParams{
    HashName:       "sha256",
    DataBlockSize:  4096,
    HashBlockSize:  4096,
    DataSize:       fileSize / 4096, // number of blocks
    HashType:       1,
    Salt:           make([]byte, 32),
    SaltSize:       32,
    HashAreaOffset: 4096,
}

vh := verity.NewVerityHash(params, dataPath, hashPath, nil)
if err := vh.Create(); err != nil {
    log.Fatalf("Failed to create hash tree: %v", err)
}

// The root hash is now available in vh.rootHash
```

### Verifying Data

```
vh := verity.NewVerityHash(params, dataPath, hashPath, rootHash)
if err := vh.Verify(); err != nil {
    log.Fatalf("Verification failed: %v", err)
}
```

## Project Status

This is an initial implementation focusing on core functionality. The API may change as we add more features.

### Planned Features

1. Command Line Interface
   - Complete veritysetup command line interface replacement
   - Drop-in replacement for all veritysetup commands

2. Additional Hash Algorithms
   - Support for SHA512
   - Support for Blake2b
   - Pluggable hash algorithm interface

3. Performance Optimizations
   - Parallel hash computation
   - Memory usage optimizations
   - Streaming support for large files

4. Additional Features
   - FEC (Forward Error Correction) support
   - Support for different salt configurations
   - Integration with Linux device-mapper
   - Support for all veritysetup options and configurations

5. Documentation
   - Detailed API documentation
   - Usage examples
   - Performance benchmarks
   - Migration guide from veritysetup to this library

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [dm-verity kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html)
- [veritysetup man page](https://man7.org/linux/man-pages/man8/veritysetup.8.html)