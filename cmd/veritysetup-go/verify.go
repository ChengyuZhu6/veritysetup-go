package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	verity "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
)

// parseVerifyArgs parses flags for the verify subcommand and returns params, paths, and root digest.
func parseVerifyArgs(args []string) (*verity.VerityParams, string, string, []byte, error) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	hashName := fs.String("hash", "sha256", "hash algorithm")
	dataBlockSize := fs.Uint("data-block-size", 4096, "data block size in bytes")
	hashBlockSize := fs.Uint("hash-block-size", 4096, "hash block size in bytes")
	saltHex := fs.String("salt", "", "salt as hex string or '-' for none")
	dataBlocks := fs.Uint64("data-blocks", 0, "number of data blocks (override file size)")
	noSuper := fs.Bool("no-superblock", false, "hash file has no superblock")
	hashOffset := fs.Uint64("hash-offset", 0, "hash area offset when no superblock")
	uuidStr := fs.String("uuid", "", "UUID (RFC4122) (ignored unless --no-superblock)")

	if err := fs.Parse(args); err != nil {
		return nil, "", "", nil, err
	}
	rest := fs.Args()
	if len(rest) != 3 {
		return nil, "", "", nil, errors.New("require <data_path> <hash_path> <root_hex>")
	}
	dataPath := rest[0]
	hashPath := rest[1]

	p := verity.DefaultVerityParams()
	p.HashName = strings.ToLower(*hashName)
	p.DataBlockSize = uint32(*dataBlockSize)
	p.HashBlockSize = uint32(*hashBlockSize)
	p.NoSuperblock = *noSuper
	p.HashAreaOffset = *hashOffset

	if !verity.IsBlockSizeValid(p.DataBlockSize) {
		return nil, "", "", nil, fmt.Errorf("invalid data block size: %d", p.DataBlockSize)
	}
	if !verity.IsBlockSizeValid(p.HashBlockSize) {
		return nil, "", "", nil, fmt.Errorf("invalid hash block size: %d", p.HashBlockSize)
	}
	if p.NoSuperblock && (p.HashAreaOffset%uint64(p.HashBlockSize) != 0) {
		return nil, "", "", nil, fmt.Errorf("hash offset %d must be aligned to hash block size %d", p.HashAreaOffset, p.HashBlockSize)
	}

	if *saltHex != "" && *saltHex != "-" {
		b := make([]byte, hex.DecodedLen(len(*saltHex)))
		n, err := hex.Decode(b, []byte(*saltHex))
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("invalid salt hex: %w", err)
		}
		p.Salt = b[:n]
		if len(p.Salt) > int(verity.MaxSaltSize) {
			return nil, "", "", nil, fmt.Errorf("salt too large: %d > %d", len(p.Salt), verity.MaxSaltSize)
		}
		p.SaltSize = uint16(len(p.Salt))
	} else {
		p.Salt = nil
		p.SaltSize = 0
	}

	if *dataBlocks != 0 {
		p.DataBlocks = *dataBlocks
	} else {
		st, err := os.Stat(dataPath)
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("stat data path: %w", err)
		}
		size := st.Size()
		if size < 0 {
			return nil, "", "", nil, fmt.Errorf("cannot determine data size; provide --data-blocks")
		}
		if size%int64(p.DataBlockSize) != 0 {
			return nil, "", "", nil, fmt.Errorf("data size %d not multiple of data block size %d", size, p.DataBlockSize)
		}
		p.DataBlocks = uint64(size / int64(p.DataBlockSize))
	}

	if *uuidStr != "" && p.NoSuperblock {
		s := strings.ToLower(strings.TrimSpace(*uuidStr))
		s = strings.ReplaceAll(s, "-", "")
		if len(s) != 32 {
			return nil, "", "", nil, fmt.Errorf("invalid uuid length: want 32 hex chars after removing hyphens")
		}
		buf := make([]byte, hex.DecodedLen(len(s)))
		if _, err := hex.Decode(buf, []byte(s)); err != nil {
			return nil, "", "", nil, fmt.Errorf("invalid uuid hex: %w", err)
		}
		if len(buf) != 16 {
			return nil, "", "", nil, fmt.Errorf("invalid uuid: need 16 bytes")
		}
		var uuidArr [16]byte
		copy(uuidArr[:], buf)
		p.UUID = uuidArr
	}

	rootArg := strings.TrimSpace(rest[2])
	if rootArg == "" {
		return nil, "", "", nil, errors.New("root hash is required")
	}
	rootBytes := make([]byte, hex.DecodedLen(len(rootArg)))
	nRoot, err := hex.Decode(rootBytes, []byte(rootArg))
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("invalid root hex: %w", err)
	}
	rootBytes = rootBytes[:nRoot]
	expectedHashSize := selectHashSize(p.HashName)
	if expectedHashSize != 0 && len(rootBytes) != expectedHashSize {
		return nil, "", "", nil, fmt.Errorf("root digest size mismatch: got %d want %d (for %s)", len(rootBytes), expectedHashSize, p.HashName)
	}

	return &p, dataPath, hashPath, rootBytes, nil
}

// runVerify performs full verification.
func runVerify(p *verity.VerityParams, dataPath, hashPath string, rootDigest []byte) error {
	v, err := verity.NewVerifier(p, dataPath, hashPath, rootDigest)
	if err != nil {
		return err
	}
	defer v.Close()

	if err := v.VerifyAll(); err != nil {
		return err
	}
	fmt.Printf("Verification succeeded\n")
	return nil
}
