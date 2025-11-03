package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
	verity "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
)

type CommonFlags struct {
	HashName      *string
	DataBlockSize *uint
	HashBlockSize *uint
	SaltHex       *string
	DataBlocks    *uint64
	NoSuper       *bool
	HashOffset    *uint64
	UUIDStr       *string
	FormatType    *uint
}

func defaultFlags(fs *flag.FlagSet) *CommonFlags {
	return &CommonFlags{
		HashName:      fs.String("hash", "", "hash algorithm"),
		DataBlockSize: fs.Uint("data-block-size", 0, "data block size in bytes"),
		HashBlockSize: fs.Uint("hash-block-size", 0, "hash block size in bytes"),
		SaltHex:       fs.String("salt", "", "salt as hex string or '-' for none"),
		DataBlocks:    fs.Uint64("data-blocks", 0, "number of data blocks (override file size)"),
		NoSuper:       fs.Bool("no-superblock", false, "omit/ignore verity superblock"),
		HashOffset:    fs.Uint64("hash-offset", 0, "hash area offset when no superblock"),
		UUIDStr:       fs.String("uuid", "", "UUID (RFC4122)"),
		FormatType:    fs.Uint("format", 1, "Format type (1 - normal, 0 - original Chrome OS)"),
	}
}

func validateAndApplyBlockSizes(p *verity.VerityParams, flags *CommonFlags) error {
	if *flags.NoSuper {
		if p.DataBlockSize == 0 {
			p.DataBlockSize = 4096
		}
		if p.HashBlockSize == 0 {
			p.HashBlockSize = 4096
		}
	}

	if *flags.DataBlockSize != 0 {
		if !utils.IsBlockSizeValid(uint32(*flags.DataBlockSize)) {
			return fmt.Errorf("invalid data block size: %d", *flags.DataBlockSize)
		}
		p.DataBlockSize = uint32(*flags.DataBlockSize)
	}

	if *flags.HashBlockSize != 0 {
		if !utils.IsBlockSizeValid(uint32(*flags.HashBlockSize)) {
			return fmt.Errorf("invalid hash block size: %d", *flags.HashBlockSize)
		}
		p.HashBlockSize = uint32(*flags.HashBlockSize)
	}

	return nil
}

func applyFlags(p *verity.VerityParams, flags *CommonFlags) {
	p.HashType = uint32(*flags.FormatType)
	p.NoSuperblock = *flags.NoSuper
	p.HashAreaOffset = *flags.HashOffset

	if *flags.HashName != "" {
		p.HashName = strings.ToLower(*flags.HashName)
	}
}
