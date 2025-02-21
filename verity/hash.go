package verity

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"os"
)

// VerityHash handles hash creation and verification
type VerityHash struct {
	params     *VerityParams
	dataDevice string
	hashDevice string
	rootHash   []byte
}

// NewVerityHash creates a new VerityHash instance
func NewVerityHash(params *VerityParams, dataDevice, hashDevice string, rootHash []byte) *VerityHash {
	return &VerityHash{
		params:     params,
		dataDevice: dataDevice,
		hashDevice: hashDevice,
		rootHash:   rootHash,
	}
}

// Verify verifies the verity hash tree
func (vh *VerityHash) Verify() error {
	return vh.createOrVerifyHash(true)
}

// Create creates the verity hash tree
func (vh *VerityHash) Create() error {
	return vh.createOrVerifyHash(false)
}

// hashTreeLevel represents a level in the hash tree
type hashTreeLevel struct {
	offset uint64
	size   uint64
}

// calculateHashLevels calculates the offsets and sizes for each level of the hash tree
func (vh *VerityHash) calculateHashLevels() ([]hashTreeLevel, error) {
	hashPerBlock := vh.params.HashBlockSize / uint32(len(vh.rootHash))
	levels := make([]hashTreeLevel, 0)

	blocks := vh.params.DataSize
	offset := vh.params.HashAreaOffset

	// Calculate each level from bottom up
	for blocks > 1 {
		level := hashTreeLevel{
			offset: offset,
			size:   blocks,
		}
		levels = append(levels, level)

		// Calculate next level
		blocks = (blocks + uint64(hashPerBlock) - 1) / uint64(hashPerBlock)
		offset += blocks * uint64(vh.params.HashBlockSize)
	}

	// Add root level
	levels = append(levels, hashTreeLevel{
		offset: offset,
		size:   1,
	})

	return levels, nil
}

// verifyHashBlock verifies a single hash block
func (vh *VerityHash) verifyHashBlock(data []byte, salt []byte) ([]byte, error) {
	h := crypto.SHA256.New() // TODO: Make hash algorithm configurable

	if vh.params.HashType == 1 { // Normal hash
		h.Write(salt)
		h.Write(data)
	} else { // Chrome OS hash
		h.Write(data)
		h.Write(salt)
	}

	return h.Sum(nil), nil
}

// readBlock reads a block from a file
func readBlock(f *os.File, offset uint64, size uint32) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := f.Seek(int64(offset), 0); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeBlock writes a block to a file
func writeBlock(f *os.File, offset uint64, data []byte) error {
	if _, err := f.Seek(int64(offset), 0); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}

func (vh *VerityHash) createOrVerifyHash(verify bool) error {
	// Open devices
	dataFile, err := os.OpenFile(vh.dataDevice, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot open data device: %v", err)
	}
	defer dataFile.Close()

	flag := os.O_RDONLY
	if !verify {
		flag = os.O_RDWR
	}
	hashFile, err := os.OpenFile(vh.hashDevice, flag, 0)
	if err != nil {
		return fmt.Errorf("cannot open hash device: %v", err)
	}
	defer hashFile.Close()

	// Calculate hash tree levels
	levels, err := vh.calculateHashLevels()
	if err != nil {
		return err
	}

	if len(levels) > VerityMaxLevels {
		return fmt.Errorf("too many tree levels: %d", len(levels))
	}

	// Process each level from bottom up
	currentHash := make([]byte, len(vh.rootHash))
	for i := 0; i < len(levels); i++ {
		level := levels[i]

		// For each block in this level
		for j := uint64(0); j < level.size; j++ {
			var blockData []byte
			var err error

			if i == 0 {
				// Read from data device for first level
				blockData, err = readBlock(dataFile, j*uint64(vh.params.DataBlockSize), vh.params.DataBlockSize)
			} else {
				// Read from hash device for other levels
				blockData, err = readBlock(hashFile, levels[i-1].offset+j*uint64(vh.params.HashBlockSize), vh.params.HashBlockSize)
			}
			if err != nil {
				return fmt.Errorf("failed to read block: %v", err)
			}

			// Calculate hash
			hash, err := vh.verifyHashBlock(blockData, vh.params.Salt)
			if err != nil {
				return fmt.Errorf("failed to calculate hash: %v", err)
			}

			if verify {
				// Read stored hash
				storedHash, err := readBlock(hashFile, level.offset+j*uint64(len(vh.rootHash)), uint32(len(vh.rootHash)))
				if err != nil {
					return fmt.Errorf("failed to read stored hash: %v", err)
				}

				// Compare hashes
				if !bytes.Equal(hash, storedHash) {
					return fmt.Errorf("hash mismatch at level %d block %d", i, j)
				}
			} else {
				// Write hash
				if err := writeBlock(hashFile, level.offset+j*uint64(len(vh.rootHash)), hash); err != nil {
					return fmt.Errorf("failed to write hash: %v", err)
				}
			}

			// Save hash for next level
			copy(currentHash, hash)
		}
	}

	// Verify/save root hash
	if verify {
		if !bytes.Equal(currentHash, vh.rootHash) {
			return fmt.Errorf("root hash mismatch")
		}
	} else {
		copy(vh.rootHash, currentHash)
	}

	return nil
}
