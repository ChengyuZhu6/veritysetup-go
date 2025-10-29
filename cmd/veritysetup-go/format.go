package main

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	verity "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
)

// runFormat performs the verity hash tree creation and prints header info.
func runFormat(p *verity.VerityParams, dataPath, hashPath string) error {
	vh := verity.NewVerityHash(p, dataPath, hashPath, nil)
	if err := vh.Create(); err != nil {
		return err
	}

	hashSize := selectHashSize(p.HashName)
	if hashSize == 0 {
		hashSize = crypto.SHA256.Size()
	}
	hashesPerBlock := p.HashBlockSize / uint32(hashSize)
	var totalHashBlocks uint64
	if hashesPerBlock == 0 {
		return fmt.Errorf("hash block size %d is too small for hash size %d", p.HashBlockSize, hashSize)
	}
	remaining := p.DataBlocks
	for {
		numBlocks := (remaining + uint64(hashesPerBlock) - 1) / uint64(hashesPerBlock)
		if remaining == 1 {
			break
		}
		totalHashBlocks += numBlocks
		remaining = numBlocks
	}

	hashDeviceSize := totalHashBlocks * uint64(p.HashBlockSize)
	if !p.NoSuperblock {
		hashDeviceSize += alignUp(uint64(verity.VeritySuperblockSize), uint64(p.HashBlockSize))
	}

	uuidStr := ""
	if p.UUID != ([16]byte{}) {
		b := make([]byte, 16)
		copy(b, p.UUID[:])
		hexStr := hex.EncodeToString(b)
		uuidStr = fmt.Sprintf("%s-%s-%s-%s-%s", hexStr[0:8], hexStr[8:12], hexStr[12:16], hexStr[16:20], hexStr[20:32])
	}

	fmt.Printf("VERITY header information for %s\n", hashPath)
	fmt.Printf("UUID:                   %s\n", uuidStr)
	fmt.Printf("Format:                 %d\n", p.HashType)
	fmt.Printf("Data blocks:            %d\n", p.DataBlocks)
	fmt.Printf("Data block size:        %d\n", p.DataBlockSize)
	fmt.Printf("Hash blocks:            %d\n", totalHashBlocks)
	fmt.Printf("Hash block size:        %d\n", p.HashBlockSize)
	fmt.Printf("Hash algorithm:         %s\n", strings.ToLower(p.HashName))
	fmt.Printf("Salt:                   %s\n", hex.EncodeToString(p.Salt))
	fmt.Printf("Root hash:              %s\n", hex.EncodeToString(vh.RootHash()))
	fmt.Printf("Hash device size:       %d [bytes]\n", hashDeviceSize)
	return nil
}

// parseFormatArgs parses and validates flags for the format subcommand,
// returning the constructed params and the data/hash paths.
func parseFormatArgs(args []string) (*verity.VerityParams, string, string, error) {
	fs := flag.NewFlagSet("format", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	hashName := fs.String("hash", "sha256", "hash algorithm")
	dataBlockSize := fs.Uint("data-block-size", 4096, "data block size in bytes")
	hashBlockSize := fs.Uint("hash-block-size", 4096, "hash block size in bytes")
	formatType := fs.Uint("format", 1, "Format type (1 - normal, 0 - original Chrome OS)")
	saltHex := fs.String("salt", "", "salt as hex string")
	uuidStr := fs.String("uuid", "", "UUID (RFC4122)")
	dataBlocks := fs.Uint64("data-blocks", 0, "number of data blocks (override file size)")
	noSuper := fs.Bool("no-superblock", false, "omit verity superblock")
	hashOffset := fs.Uint64("hash-offset", 0, "hash area offset when no superblock")

	if err := fs.Parse(args); err != nil {
		return nil, "", "", err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return nil, "", "", errors.New("require <data_path> and <hash_path>")
	}
	dataPath := rest[0]
	hashPath := rest[1]

	p := verity.DefaultVerityParams()
	p.HashName = *hashName
	p.DataBlockSize = uint32(*dataBlockSize)
	p.HashBlockSize = uint32(*hashBlockSize)
	p.HashType = uint32(*formatType)
	p.NoSuperblock = *noSuper
	p.HashAreaOffset = *hashOffset

	if !verity.IsBlockSizeValid(p.DataBlockSize) {
		return nil, "", "", fmt.Errorf("invalid data block size: %d", p.DataBlockSize)
	}
	if !verity.IsBlockSizeValid(p.HashBlockSize) {
		return nil, "", "", fmt.Errorf("invalid hash block size: %d", p.HashBlockSize)
	}
	if p.NoSuperblock && (p.HashAreaOffset%uint64(p.HashBlockSize) != 0) {
		return nil, "", "", fmt.Errorf("hash offset %d must be aligned to hash block size %d", p.HashAreaOffset, p.HashBlockSize)
	}

	if *saltHex != "" && *saltHex != "-" {
		b := make([]byte, hex.DecodedLen(len(*saltHex)))
		n, err := hex.Decode(b, []byte(*saltHex))
		if err != nil {
			return nil, "", "", fmt.Errorf("invalid salt hex: %w", err)
		}
		p.Salt = b[:n]
		if len(p.Salt) > int(verity.MaxSaltSize) {
			return nil, "", "", fmt.Errorf("salt too large: %d > %d", len(p.Salt), verity.MaxSaltSize)
		}
		p.SaltSize = uint16(len(p.Salt))
	} else {
		p.Salt = nil
		p.SaltSize = 0
	}

	if *uuidStr != "" {
		s := strings.ToLower(strings.TrimSpace(*uuidStr))
		s = strings.ReplaceAll(s, "-", "")
		if len(s) != 32 {
			return nil, "", "", fmt.Errorf("invalid uuid length: want 32 hex chars after removing hyphens")
		}
		buf := make([]byte, hex.DecodedLen(len(s)))
		if _, err := hex.Decode(buf, []byte(s)); err != nil {
			return nil, "", "", fmt.Errorf("invalid uuid hex: %w", err)
		}
		if len(buf) != 16 {
			return nil, "", "", fmt.Errorf("invalid uuid: need 16 bytes")
		}
		var uuidArr [16]byte
		copy(uuidArr[:], buf)
		p.UUID = uuidArr
	}

	if *dataBlocks != 0 {
		p.DataBlocks = *dataBlocks
	} else {
		st, err := os.Stat(dataPath)
		if err != nil {
			return nil, "", "", fmt.Errorf("stat data path: %w", err)
		}
		size := st.Size()
		if size < 0 {
			return nil, "", "", fmt.Errorf("cannot determine data size; provide --data-blocks")
		}
		if size%int64(p.DataBlockSize) != 0 {
			return nil, "", "", fmt.Errorf("data size %d not multiple of data block size %d", size, p.DataBlockSize)
		}
		p.DataBlocks = uint64(size / int64(p.DataBlockSize))
	}

	return &p, dataPath, hashPath, nil
}

func selectHashSize(name string) int {
	switch strings.ToLower(name) {
	case "sha1":
		return crypto.SHA1.Size()
	case "sha256":
		return crypto.SHA256.Size()
	case "sha512":
		return crypto.SHA512.Size()
	default:
		return crypto.SHA256.Size()
	}
}

func alignUp(x, align uint64) uint64 {
	if align == 0 {
		return x
	}
	rem := x % align
	if rem == 0 {
		return x
	}
	return x + (align - rem)
}
