package verity

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

type Verifier struct {
	vh       *VerityHash
	dataFile *os.File
	hashFile *os.File
}

func NewVerifier(params *VerityParams, dataPath, hashPath string, rootDigest []byte) (*Verifier, error) {
	vh := NewVerityHash(
		params.HashName,
		params.DataBlockSize, params.HashBlockSize,
		params.DataBlocks,
		params.HashType,
		params.Salt,
		params.HashAreaOffset,
		dataPath, hashPath,
		rootDigest,
	)

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
	vh := NewVerityHash(
		params.HashName,
		params.DataBlockSize, params.HashBlockSize,
		params.DataBlocks,
		params.HashType,
		params.Salt,
		params.HashAreaOffset,
		dataPath, hashPath,
		nil,
	)

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
	if params == nil {
		return errors.New("verity: nil params")
	}

	if params.HashType > VerityMaxHashType {
		return fmt.Errorf("verity: unsupported hash type %d", params.HashType)
	}
	if params.HashName == "" {
		return errors.New("verity: hash algorithm required")
	}

	if params.SaltSize > MaxSaltSize {
		return fmt.Errorf("salt size %d exceeds maximum of %d bytes", params.SaltSize, MaxSaltSize)
	}

	if digestSize > VerityMaxDigestSize {
		return fmt.Errorf("digest size %d exceeds maximum of %d bytes", digestSize, VerityMaxDigestSize)
	}

	if !IsBlockSizeValid(params.DataBlockSize) {
		return fmt.Errorf("invalid data block size: %d", params.DataBlockSize)
	}
	if !IsBlockSizeValid(params.HashBlockSize) {
		return fmt.Errorf("invalid hash block size: %d", params.HashBlockSize)
	}

	if uint64MultOverflow(params.DataBlocks, uint64(params.DataBlockSize)) {
		return fmt.Errorf("data device offset overflow: %d blocks * %d bytes",
			params.DataBlocks, params.DataBlockSize)
	}

	if params.NoSuperblock {
		if params.HashAreaOffset%uint64(params.HashBlockSize) != 0 {
			return fmt.Errorf("hash offset %d must be aligned to hash block size %d", params.HashAreaOffset, params.HashBlockSize)
		}
	} else {
		if params.HashAreaOffset == 0 {
			return errors.New("verity: hash area offset not initialised for superblock mode")
		}
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
		hashBlockSize:  params.HashBlockSize,
		hashAreaOffset: params.HashAreaOffset,
		dataBlocks:     params.DataBlocks,
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

	levels, err := vh.hashLevels(vh.dataBlocks)
	if err != nil {
		return 0, err
	}

	if len(levels) == 0 {
		return 0, nil
	}

	hashPosition := (levels[len(levels)-1].offset + levels[len(levels)-1].numBlocks*uint64(vh.hashBlockSize)) / uint64(vh.hashBlockSize)

	return hashPosition, nil
}

// HashOffsetBlock calculates hash offset in hash blocks.
// This corresponds to VERITY_hash_offset_block in verity.c
func HashOffsetBlock(params *VerityParams) uint64 {
	hashOffset := params.HashAreaOffset

	if params.NoSuperblock {
		return hashOffset / uint64(params.HashBlockSize)
	}

	// Add superblock size and align to hash block size
	hashOffset += VeritySuperblockSize
	hashOffset += uint64(params.HashBlockSize) - 1

	return hashOffset / uint64(params.HashBlockSize)
}

// GenerateUUID generates a new UUID string for verity device.
// This corresponds to VERITY_UUID_generate in verity.c
func GenerateUUID() (string, error) {
	newUUID := uuid.New()
	return newUUID.String(), nil
}

// ReadVeritySuperblock reads verity superblock from a device at specified offset
// and populates the params structure.
// This corresponds to VERITY_read_sb in verity.c
func ReadVeritySuperblock(device io.ReaderAt, sbOffset uint64, params *VerityParams) (string, error) {
	if params == nil {
		return "", errors.New("verity: nil params")
	}

	if params.NoSuperblock {
		return "", errors.New("verity: device does not use on-disk header")
	}

	if sbOffset%diskSectorSize != 0 {
		return "", errors.New("verity: unsupported hash offset (not 512-byte aligned)")
	}

	sb, err := ReadSuperblock(device, sbOffset)
	if err != nil {
		return "", err
	}

	// Adopt parameters from superblock
	if err := AdoptParamsFromSuperblock(params, sb, sbOffset); err != nil {
		return "", err
	}

	// Return UUID string
	uuidStr, err := sb.UUIDString()
	if err != nil {
		return "", err
	}

	return uuidStr, nil
}

// WriteSuperblock writes verity superblock to a device at specified offset.
// This corresponds to VERITY_write_sb in verity.c
func WriteSuperblock(device io.WriterAt, sbOffset uint64, uuidString string, params *VerityParams) error {
	if params == nil {
		return errors.New("verity: nil params")
	}

	if params.NoSuperblock {
		return errors.New("verity: device does not use on-disk header")
	}

	if uuidString == "" {
		return errors.New("verity: UUID required")
	}

	// Parse UUID
	parsedUUID, err := uuid.Parse(uuidString)
	if err != nil {
		return fmt.Errorf("verity: wrong UUID format: %w", err)
	}

	// Set UUID in params
	copy(params.UUID[:], parsedUUID[:])

	// Build superblock from params
	sb, err := BuildSuperblockFromParams(params)
	if err != nil {
		return err
	}

	// Write superblock
	if err := sb.WriteSuperblock(device, sbOffset); err != nil {
		return fmt.Errorf("verity: error during update of verity header: %w", err)
	}

	return nil
}

// VerifyParams verifies verity parameters and optionally performs userspace verification.
// This corresponds to VERITY_verify_params in verity.c
func VerifyParams(params *VerityParams, dataDevice, hashDevice string, rootHash []byte, checkHash bool) error {
	if params == nil {
		return errors.New("verity: nil params")
	}

	if rootHash == nil {
		return errors.New("verity: root hash required")
	}

	log.Printf("Verifying VERITY device using hash %s", params.HashName)

	if !checkHash {
		// No userspace verification requested
		return nil
	}

	log.Printf("Verification of VERITY data in userspace required")

	// Perform userspace verification
	verifier, err := NewVerifier(params, dataDevice, hashDevice, rootHash)
	if err != nil {
		return err
	}
	defer verifier.Close()

	if err := verifier.VerifyAll(); err != nil {
		return fmt.Errorf("verity: verification failed: %w", err)
	}

	return nil
}

// DumpInfo dumps verity device information.
// This corresponds to VERITY_dump in verity.c
func DumpInfo(params *VerityParams, rootHash []byte) (string, error) {
	if params == nil {
		return "", errors.New("verity: nil params")
	}

	digestSize := getHashSize(params.HashName)
	if digestSize <= 0 {
		return "", fmt.Errorf("verity: unsupported hash algorithm %s", params.HashName)
	}

	hashBlocks, err := VerityHashBlocks(params, digestSize)
	if err != nil {
		return "", err
	}

	verityBlocks := HashOffsetBlock(params) + hashBlocks

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("VERITY header information\\n"))
	sb.WriteString(fmt.Sprintf("Hash type:       \t%d\\n", params.HashType))
	sb.WriteString(fmt.Sprintf("Data blocks:     \t%d\\n", params.DataBlocks))
	sb.WriteString(fmt.Sprintf("Data block size: \t%d [bytes]\\n", params.DataBlockSize))
	sb.WriteString(fmt.Sprintf("Hash blocks:     \t%d\\n", hashBlocks))
	sb.WriteString(fmt.Sprintf("Hash block size: \t%d [bytes]\\n", params.HashBlockSize))
	sb.WriteString(fmt.Sprintf("Hash algorithm:  \t%s\\n", params.HashName))

	sb.WriteString("Salt:            \t")
	if params.SaltSize > 0 {
		sb.WriteString(fmt.Sprintf("%x", params.Salt))
	} else {
		sb.WriteString("-")
	}
	sb.WriteString("\\n")

	if rootHash != nil {
		sb.WriteString(fmt.Sprintf("Root hash:      \t%x\\n", rootHash))
	}

	if params.HashAreaOffset == 0 {
		sb.WriteString(fmt.Sprintf("Hash device size: \t%d [bytes]\\n", verityBlocks*uint64(params.HashBlockSize)))
	}

	return sb.String(), nil
}

// getHashSize returns the digest size for a given hash algorithm name.
func getHashSize(hashName string) int {
	hashMap := map[string]crypto.Hash{
		"sha1":   crypto.SHA1,
		"sha256": crypto.SHA256,
		"sha512": crypto.SHA512,
	}

	name := strings.ToLower(strings.TrimSpace(hashName))
	if h, ok := hashMap[name]; ok && h.Available() {
		return h.Size()
	}
	return -1
}

func HighLevelVerify(params *VerityParams, dataDevice, hashDevice string, rootHash []byte) error {
	if params == nil {
		return errors.New("verity: nil params")
	}

	if !params.NoSuperblock {
		hashFile, err := os.Open(hashDevice)
		if err != nil {
			return fmt.Errorf("cannot open hash device: %w", err)
		}
		defer hashFile.Close()

		sb, err := ReadSuperblock(hashFile, params.HashAreaOffset)
		if err != nil {
			return err
		}

		if err := AdoptParamsFromSuperblock(params, sb, params.HashAreaOffset); err != nil {
			return err
		}
	}

	vh := NewVerityHash(
		params.HashName,
		params.DataBlockSize, params.HashBlockSize,
		params.DataBlocks,
		params.HashType,
		params.Salt,
		params.HashAreaOffset,
		dataDevice, hashDevice,
		rootHash,
	)

	if err := validateParams(params, vh.hashFunc.Size()); err != nil {
		return err
	}

	return vh.createOrVerifyHashTree(true)
}

func HighLevelCreate(params *VerityParams, dataDevice, hashDevice string) ([]byte, error) {
	if params == nil {
		return nil, errors.New("verity: nil params")
	}

	if !params.NoSuperblock {
		sb, err := BuildSuperblockFromParams(params)
		if err != nil {
			return nil, err
		}

		hashFile, err := os.OpenFile(hashDevice, os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("cannot open hash device: %w", err)
		}
		defer hashFile.Close()

		if err := sb.WriteSuperblock(hashFile, params.HashAreaOffset); err != nil {
			return nil, err
		}

		if err := AdoptParamsFromSuperblock(params, sb, params.HashAreaOffset); err != nil {
			return nil, err
		}
	}

	vh := NewVerityHash(
		params.HashName,
		params.DataBlockSize, params.HashBlockSize,
		params.DataBlocks,
		params.HashType,
		params.Salt,
		params.HashAreaOffset,
		dataDevice, hashDevice,
		nil,
	)

	if err := validateParams(params, vh.hashFunc.Size()); err != nil {
		return nil, err
	}

	if err := vh.createOrVerifyHashTree(false); err != nil {
		return nil, err
	}

	return vh.RootHash(), nil
}

func VerifyBlock(params *VerityParams, hashName string, data, salt, expectedHash []byte) error {
	vh := &VerityHash{
		hashType: params.HashType,
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
