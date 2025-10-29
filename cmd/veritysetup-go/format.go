package main

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"fmt"
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
