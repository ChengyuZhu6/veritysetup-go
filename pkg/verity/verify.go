package verity

import (
	"bytes"
	"crypto"
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

type Verifier struct {
	vh       *VerityHash
	dataFile *os.File
	hashFile *os.File
}

func NewVerifier(params *VerityParams, dataPath, hashPath string, rootDigest []byte) (*Verifier, error) {
	vh := NewVerityHash(params, dataPath, hashPath, rootDigest)

	if err := validateParams(params, vh.hashFunc.Size()); err != nil {
		return nil, err
	}

	dataFile, err := os.Open(dataPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open data device: %w", err)
	}

	hashFile, err := os.Open(hashPath)
	if err != nil {
		dataFile.Close()
		return nil, fmt.Errorf("cannot open hash device: %w", err)
	}

	return &Verifier{
		vh:       vh,
		dataFile: dataFile,
		hashFile: hashFile,
	}, nil
}

func (v *Verifier) Close() error {
	var first error
	if v.dataFile != nil {
		if err := v.dataFile.Close(); err != nil {
			first = err
		}
	}
	if v.hashFile != nil {
		if err := v.hashFile.Close(); err != nil {
			if first == nil {
				first = err
			}
		}
	}
	return first
}

func (v *Verifier) VerifyAll() error {
	return v.vh.createOrVerifyHashTree(true)
}

type Creator struct {
	vh *VerityHash
}

func NewCreator(params *VerityParams, dataPath, hashPath string) (*Creator, error) {
	vh := NewVerityHash(params, dataPath, hashPath, nil)

	if err := validateParams(params, vh.hashFunc.Size()); err != nil {
		return nil, err
	}

	return &Creator{vh: vh}, nil
}

func (c *Creator) Create() ([]byte, error) {
	if err := c.vh.createOrVerifyHashTree(false); err != nil {
		return nil, err
	}
	return c.vh.RootHash(), nil
}

func validateParams(params *VerityParams, digestSize int) error {
	if params.SaltSize > 256 {
		return fmt.Errorf("salt size %d exceeds maximum of 256 bytes", params.SaltSize)
	}

	if digestSize > VerityMaxDigestSize {
		return fmt.Errorf("digest size %d exceeds maximum of %d bytes", digestSize, VerityMaxDigestSize)
	}

	if uint64MultOverflow(params.DataBlocks, uint64(params.DataBlockSize)) {
		return fmt.Errorf("data device offset overflow: %d blocks * %d bytes",
			params.DataBlocks, params.DataBlockSize)
	}

	pageSize := uint32(unix.Getpagesize())
	if params.DataBlockSize > pageSize {
		log.Printf("WARNING: Kernel cannot activate device if data block size (%d) exceeds page size (%d)",
			params.DataBlockSize, pageSize)
	}

	return nil
}

func uint64MultOverflow(a, b uint64) bool {
	if b == 0 {
		return false
	}
	result := a * b
	return result/b != a
}

func VerityHashBlocks(params *VerityParams, digestSize int) (uint64, error) {
	vh := &VerityHash{
		params: params,
		hashFunc: func() crypto.Hash {
			switch digestSize {
			case 20:
				return crypto.SHA1
			case 32:
				return crypto.SHA256
			case 64:
				return crypto.SHA512
			default:
				return crypto.SHA256
			}
		}(),
	}

	levels, err := vh.hashLevels(params.DataBlocks)
	if err != nil {
		return 0, err
	}

	if len(levels) == 0 {
		return 0, nil
	}

	lastLevel := levels[len(levels)-1]
	hashPosition := (lastLevel.offset + lastLevel.numBlocks*uint64(params.HashBlockSize)) / uint64(params.HashBlockSize)

	return hashPosition, nil
}

func HighLevelVerify(params *VerityParams, dataDevice, hashDevice string, rootHash []byte) error {
	vh := NewVerityHash(params, dataDevice, hashDevice, rootHash)

	if err := validateParams(params, vh.hashFunc.Size()); err != nil {
		return err
	}

	if !params.NoSuperblock {
		hashFile, err := os.Open(hashDevice)
		if err != nil {
			return fmt.Errorf("cannot open hash device: %w", err)
		}
		defer hashFile.Close()

		sbData := make([]byte, VeritySuperblockSize)
		if _, err := hashFile.Read(sbData); err != nil {
			return fmt.Errorf("read superblock: %w", err)
		}

		sb, err := DeserializeSuperblock(sbData)
		if err != nil {
			return err
		}

		if err := validateAndAdoptSuperblock(params, sb); err != nil {
			return err
		}
	}

	return vh.createOrVerifyHashTree(true)
}

func HighLevelCreate(params *VerityParams, dataDevice, hashDevice string) ([]byte, error) {
	vh := NewVerityHash(params, dataDevice, hashDevice, nil)

	if err := validateParams(params, vh.hashFunc.Size()); err != nil {
		return nil, err
	}

	if !params.NoSuperblock {
		sb, err := buildSuperblockFromParams(params)
		if err != nil {
			return nil, err
		}

		data, err := sb.Serialize()
		if err != nil {
			return nil, err
		}

		hashFile, err := os.OpenFile(hashDevice, os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("cannot open hash device: %w", err)
		}
		defer hashFile.Close()

		if _, err := hashFile.Write(data); err != nil {
			return nil, fmt.Errorf("write superblock: %w", err)
		}

		params.HashAreaOffset = alignUp(VeritySuperblockSize, uint64(params.HashBlockSize))
	}

	if err := vh.createOrVerifyHashTree(false); err != nil {
		return nil, err
	}

	return vh.RootHash(), nil
}

func VerifyBlock(params *VerityParams, hashName string, data, salt, expectedHash []byte) error {
	vh := &VerityHash{
		params: params,
		hashFunc: func() crypto.Hash {
			hashMap := map[string]crypto.Hash{
				"sha256": crypto.SHA256,
				"sha512": crypto.SHA512,
				"sha1":   crypto.SHA1,
			}
			if h, ok := hashMap[hashName]; ok && h.Available() {
				return h
			}
			return crypto.SHA256
		}(),
	}

	calculatedHash, err := vh.verifyHashBlock(data, salt)
	if err != nil {
		return err
	}

	if !bytes.Equal(calculatedHash, expectedHash) {
		return fmt.Errorf("block hash mismatch")
	}

	return nil
}
