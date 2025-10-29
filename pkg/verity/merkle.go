package verity

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"io"
	"os"
)

// VerityHash builds and verifies a dm-verity hash tree over a data device.
type VerityHash struct {
	params     *VerityParams
	dataDevice string
	hashDevice string
	rootHash   []byte
	hashFunc   crypto.Hash
}

// NewVerityHash creates a VerityHash with the provided parameters and devices.
func NewVerityHash(p *VerityParams, dataDevice, hashDevice string, rootHash []byte) *VerityHash {
	var hashFunc crypto.Hash
	switch p.HashName {
	case "sha256":
		hashFunc = crypto.SHA256
	case "sha512":
		hashFunc = crypto.SHA512
	case "sha1":
		hashFunc = crypto.SHA1
	default:
		hashFunc = crypto.SHA256
	}
	if !hashFunc.Available() {
		hashFunc = crypto.SHA256
	}

	hashSize := hashFunc.Size()
	vh := &VerityHash{
		params:     p,
		dataDevice: dataDevice,
		hashDevice: hashDevice,
		rootHash:   make([]byte, hashSize),
		hashFunc:   hashFunc,
	}
	if rootHash != nil {
		copy(vh.rootHash, rootHash)
	}
	return vh
}

// Verify verifies the verity hash tree.
func (vh *VerityHash) Verify() error {
	return vh.createOrVerifyHash(true)
}

// Create creates the verity hash tree.
func (vh *VerityHash) Create() error {
	return vh.createOrVerifyHash(false)
}

type hashTreeLevel struct {
	offset    uint64 // byte offset of this level's first block in hash file
	numHashes uint64 // number of hashes at this level
	numBlocks uint64 // number of blocks occupied by this level
}

func (vh *VerityHash) calculateHashLevels() ([]hashTreeLevel, error) {
	hashSize := vh.hashFunc.Size()
	hashesPerBlock := vh.params.HashBlockSize / uint32(hashSize)
	if hashesPerBlock == 0 {
		return nil, fmt.Errorf("hash block size %d is too small for hash size %d", vh.params.HashBlockSize, hashSize)
	}

	var levels []hashTreeLevel
	remainingHashes := vh.params.DataBlocks

	for {
		if len(levels) >= VerityMaxLevels {
			return nil, fmt.Errorf("hash tree exceeds maximum levels: %d", len(levels))
		}
		numBlocks := (remainingHashes + uint64(hashesPerBlock) - 1) / uint64(hashesPerBlock)
		levels = append(levels, hashTreeLevel{
			numHashes: remainingHashes,
			numBlocks: numBlocks,
		})
		if remainingHashes == 1 {
			break
		}
		remainingHashes = numBlocks
	}

	nextOffset := vh.params.HashAreaOffset
	for i := len(levels) - 2; i >= 0; i-- {
		levels[i].offset = nextOffset
		nextOffset += levels[i].numBlocks * uint64(vh.params.HashBlockSize)
	}
	levels[len(levels)-1].offset = 0
	return levels, nil
}

func (vh *VerityHash) verifyHashBlock(data []byte, salt []byte) ([]byte, error) {
	h := vh.hashFunc.New()
	if vh.params.HashType == 1 {
		if len(salt) > 0 {
			h.Write(salt)
		}
		h.Write(data)
	} else {
		h.Write(data)
		if len(salt) > 0 {
			h.Write(salt)
		}
	}
	return h.Sum(nil), nil
}

func readBlock(f *os.File, offset uint64, size uint32) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := f.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeBlock(f *os.File, offset uint64, data []byte) error {
	if _, err := f.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}

func (vh *VerityHash) createOrVerifyHash(verify bool) error {
	dataFile, hashFile, err := vh.openDeviceFiles(verify)
	if err != nil {
		return fmt.Errorf("failed to open device files: %w", err)
	}
	defer dataFile.Close()
	defer hashFile.Close()

	if err := vh.prepareHashArea(hashFile, verify); err != nil {
		return err
	}
	levels, err := vh.calculateHashLevels()
	if err != nil {
		return fmt.Errorf("failed to calculate hash levels: %w", err)
	}
	if len(levels) > VerityMaxLevels {
		return fmt.Errorf("hash tree exceeds maximum levels: %d", len(levels))
	}
	hashBuffers := vh.createHashBuffers(levels)
	currentHash, err := vh.processHashLevels(levels, hashBuffers, dataFile, hashFile, verify)
	if err != nil {
		return err
	}
	return vh.finalizeRootHash(currentHash, verify)
}

func (vh *VerityHash) prepareHashArea(hashFile *os.File, verify bool) error {
	if vh.params.NoSuperblock {
		if vh.params.HashAreaOffset%uint64(vh.params.HashBlockSize) != 0 {
			return fmt.Errorf("hash area offset %d not aligned to hash block size %d", vh.params.HashAreaOffset, vh.params.HashBlockSize)
		}
		return nil
	}

	if verify {
		sbData, err := readBlock(hashFile, 0, VeritySuperblockSize)
		if err != nil {
			return fmt.Errorf("read superblock: %w", err)
		}
		sb, err := DeserializeSuperblock(sbData)
		if err != nil {
			return err
		}
		if err := validateAndAdoptSuperblock(vh.params, sb); err != nil {
			return err
		}
		return nil
	}

	sb, err := buildSuperblockFromParams(vh.params)
	if err != nil {
		return err
	}
	data, err := sb.Serialize()
	if err != nil {
		return err
	}
	if err := writeBlock(hashFile, 0, data); err != nil {
		return fmt.Errorf("write superblock: %w", err)
	}
	vh.params.HashAreaOffset = alignUp(VeritySuperblockSize, uint64(vh.params.HashBlockSize))
	return nil
}

func (vh *VerityHash) openDeviceFiles(verify bool) (*os.File, *os.File, error) {
	dataFile, err := os.OpenFile(vh.dataDevice, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open data device: %w", err)
	}
	flag := os.O_RDONLY
	if !verify {
		flag = os.O_RDWR
	}
	hashFile, err := os.OpenFile(vh.hashDevice, flag, 0)
	if err != nil {
		dataFile.Close()
		return nil, nil, fmt.Errorf("cannot open hash device: %w", err)
	}
	return dataFile, hashFile, nil
}

func (vh *VerityHash) createHashBuffers(levels []hashTreeLevel) [][]byte {
	hashSize := vh.hashFunc.Size()
	hashBuffers := make([][]byte, len(levels))
	for i := range hashBuffers {
		hashBuffers[i] = make([]byte, int(levels[i].numHashes)*hashSize)
	}
	return hashBuffers
}

func (vh *VerityHash) processHashLevels(levels []hashTreeLevel, hashBuffers [][]byte, dataFile, hashFile *os.File, verify bool) ([]byte, error) {
	hashSize := uint32(vh.hashFunc.Size())
	currentHash := make([]byte, int(hashSize))
	for i := 0; i < len(levels); i++ {
		for j := uint64(0); j < levels[i].numHashes; j++ {
			blockData, err := vh.readBlockData(i, j, hashSize, hashBuffers, dataFile)
			if err != nil {
				return nil, err
			}
			hash, err := vh.verifyHashBlock(blockData, vh.params.Salt)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate hash at level %d block %d: %w", i, j, err)
			}
			if err := vh.handleHashResult(i, j, hash, hashBuffers, hashFile, levels, verify); err != nil {
				return nil, err
			}
			copy(currentHash, hash)
		}
	}
	return currentHash, nil
}

func (vh *VerityHash) readBlockData(level int, blockNum uint64, hashSize uint32, hashBuffers [][]byte, dataFile *os.File) ([]byte, error) {
	if level == 0 {
		return readBlock(dataFile, blockNum*uint64(vh.params.DataBlockSize), vh.params.DataBlockSize)
	}
	hashPerBlock := vh.params.HashBlockSize / uint32(hashSize)
	blockStart := blockNum * uint64(hashPerBlock) * uint64(hashSize)
	blockEnd := blockStart + uint64(hashPerBlock*hashSize)
	if blockEnd > uint64(len(hashBuffers[level-1])) {
		blockEnd = uint64(len(hashBuffers[level-1]))
	}
	blockData := make([]byte, vh.params.HashBlockSize)
	copy(blockData, hashBuffers[level-1][blockStart:blockEnd])
	return blockData, nil
}

func (vh *VerityHash) handleHashResult(level int, hashIndex uint64, hash []byte, hashBuffers [][]byte, hashFile *os.File, levels []hashTreeLevel, verify bool) error {
	copy(hashBuffers[level][hashIndex*uint64(vh.hashFunc.Size()):], hash)

	hashSize := uint32(vh.hashFunc.Size())
	hashesPerBlock := vh.params.HashBlockSize / hashSize
	blockIndex := hashIndex / uint64(hashesPerBlock)
	intra := (hashIndex % uint64(hashesPerBlock)) * uint64(hashSize)
	offset := levels[level].offset + blockIndex*uint64(vh.params.HashBlockSize) + intra

	isLastLevel := level == len(levels)-1

	if verify {
		if isLastLevel {
			return nil
		}
		storedHash, err := readBlock(hashFile, offset, hashSize)
		if err != nil {
			return fmt.Errorf("failed to read stored hash at level %d index %d: %w", level, hashIndex, err)
		}
		if !bytes.Equal(hash, storedHash) {
			return fmt.Errorf("hash mismatch at level %d index %d", level, hashIndex)
		}
		return nil
	}
	if isLastLevel {
		return nil
	}
	if err := writeBlock(hashFile, offset, hash); err != nil {
		return fmt.Errorf("failed to write hash at level %d index %d: %w", level, hashIndex, err)
	}
	return nil
}

func (vh *VerityHash) finalizeRootHash(currentHash []byte, verify bool) error {
	if verify {
		if !bytes.Equal(currentHash, vh.rootHash) {
			return fmt.Errorf("root hash verification failed")
		}
		return nil
	}
	copy(vh.rootHash, currentHash)
	return nil
}

// RootHash returns a copy of the computed root hash digest.
func (vh *VerityHash) RootHash() []byte {
	out := make([]byte, len(vh.rootHash))
	copy(out, vh.rootHash)
	return out
}
