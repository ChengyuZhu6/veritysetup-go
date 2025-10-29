package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	verity "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "format":
		p, dataPath, hashPath, err := parseFormatArgs(os.Args[2:])
		if err != nil {
			usage()
			log.Fatalf("format: %v", err)
		}

		if err := runFormat(p, dataPath, hashPath); err != nil {
			log.Fatalf("format: %v", err)
		}
	case "-h", "--help", "help":
		usage()
	default:
		log.Fatalf("unknown subcommand: %s", cmd)
	}
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

	if *saltHex != "" {
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

func usage() {
	prog := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s format [options] <data_path> <hash_path>\n", prog)
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  --hash <sha1|sha256|sha512>        Hash algorithm (default sha256)\n")
	fmt.Fprintf(os.Stderr, "  --data-block-size <bytes>          Data block size (default 4096)\n")
	fmt.Fprintf(os.Stderr, "  --hash-block-size <bytes>          Hash block size (default 4096)\n")
	fmt.Fprintf(os.Stderr, "  --format <0|1>                     Format type (1 - normal, 0 - original Chrome OS)\n")
	fmt.Fprintf(os.Stderr, "  --salt <hex>                        Salt as hex (optional)\n")
	fmt.Fprintf(os.Stderr, "  --uuid <uuid>                       UUID (e.g. 123e4567-e89b-12d3-a456-426614174000)\n")
	fmt.Fprintf(os.Stderr, "  --data-blocks <n>                  Data blocks (override file size)\n")
	fmt.Fprintf(os.Stderr, "  --no-superblock                    Do not write superblock\n")
	fmt.Fprintf(os.Stderr, "  --hash-offset <bytes>              Hash area offset (when --no-superblock)\n")
}
