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

type VerityHash struct {
	params     *VerityParams
	dataDevice string
	hashDevice string
	rootHash   []byte
	hashFunc   crypto.Hash
}

type hashTreeLevel struct {
	offset    uint64
	numHashes uint64
	numBlocks uint64
}

func NewVerityHash(p *VerityParams, dataDevice, hashDevice string, rootHash []byte) *VerityHash {
	hashMap := map[string]crypto.Hash{
		"sha256": crypto.SHA256,
		"sha512": crypto.SHA512,
		"sha1":   crypto.SHA1,
	}

	hashFunc := crypto.SHA256
	if h, ok := hashMap[p.HashName]; ok && h.Available() {
		hashFunc = h
	}

	vh := &VerityHash{
		params:     p,
		dataDevice: dataDevice,
		hashDevice: hashDevice,
		rootHash:   make([]byte, hashFunc.Size()),
		hashFunc:   hashFunc,
	}
	if rootHash != nil {
		copy(vh.rootHash, rootHash)
	}
	return vh
}

func (vh *VerityHash) Verify() error {
	return vh.createOrVerifyHash(true)
}

func (vh *VerityHash) Create() error {
	return vh.createOrVerifyHash(false)
}

func (vh *VerityHash) calculateHashLevels() ([]hashTreeLevel, error) {
	hashSize := uint32(vh.hashFunc.Size())
	digestSizeFull := vh.getDigestSizeFull(hashSize)
	hashesPerBlock := vh.params.HashBlockSize / digestSizeFull

	if hashesPerBlock == 0 {
		return nil, fmt.Errorf("hash block size %d is too small for digest size %d",
			vh.params.HashBlockSize, digestSizeFull)
	}

	var levels []hashTreeLevel
	remainingHashes := vh.params.DataBlocks

	for remainingHashes > 0 {
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

func (vh *VerityHash) verifyHashBlock(data, salt []byte) ([]byte, error) {
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
	_, err := io.ReadFull(f, buf)
	return buf, err
}

func writeBlock(f *os.File, offset uint64, data []byte) error {
	if _, err := f.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}
	_, err := f.Write(data)
	return err
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

	if !verify {
		var totalBytes uint64
		for i := 0; i < len(levels)-1; i++ {
			totalBytes += levels[i].numBlocks * uint64(vh.params.HashBlockSize)
		}
		if err := hashFile.Truncate(int64(vh.params.HashAreaOffset + totalBytes)); err != nil {
			return fmt.Errorf("preallocate hash file: %w", err)
		}
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
			return fmt.Errorf("hash area offset %d not aligned to hash block size %d",
				vh.params.HashAreaOffset, vh.params.HashBlockSize)
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
		return validateAndAdoptSuperblock(vh.params, sb)
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

	hashFlag := os.O_RDWR
	if verify {
		hashFlag = os.O_RDONLY
	}

	hashFile, err := os.OpenFile(vh.hashDevice, hashFlag, 0)
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
	digestSizeFull := vh.getDigestSizeFull(hashSize)
	hashesPerBlock := vh.params.HashBlockSize / digestSizeFull
	currentHash := make([]byte, int(hashSize))

	for level := 0; level < len(levels); level++ {
		isLastLevel := level == len(levels)-1
		for blockIdx := uint64(0); blockIdx < levels[level].numBlocks; blockIdx++ {
			if err := vh.processHashBlock(level, blockIdx, levels, hashBuffers, dataFile, hashFile, verify, currentHash, hashesPerBlock, hashSize, digestSizeFull, isLastLevel); err != nil {
				return nil, err
			}
		}
	}
	return currentHash, nil
}

func (vh *VerityHash) processHashBlock(level int, blockIdx uint64, levels []hashTreeLevel, hashBuffers [][]byte, dataFile, hashFile *os.File, verify bool, currentHash []byte, hashesPerBlock, hashSize, digestSizeFull uint32, isLastLevel bool) error {
	hashBlock := make([]byte, vh.params.HashBlockSize)
	hashBlockPos := uint64(0)

	startHashIdx := blockIdx * uint64(hashesPerBlock)
	endHashIdx := startHashIdx + uint64(hashesPerBlock)
	if endHashIdx > levels[level].numHashes {
		endHashIdx = levels[level].numHashes
	}

	for hashIdx := startHashIdx; hashIdx < endHashIdx; hashIdx++ {
		var blockData []byte
		var err error

		if level == 0 {
			blockData, err = readBlock(dataFile, hashIdx*uint64(vh.params.DataBlockSize), vh.params.DataBlockSize)
		} else {
			prevLevelOffset := levels[level-1].offset + hashIdx*uint64(vh.params.HashBlockSize)
			blockData, err = readBlock(hashFile, prevLevelOffset, vh.params.HashBlockSize)
		}
		if err != nil {
			return err
		}

		hash, err := vh.verifyHashBlock(blockData, vh.params.Salt)
		if err != nil {
			return fmt.Errorf("failed to calculate hash at level %d hash %d: %w", level, hashIdx, err)
		}

		copy(hashBuffers[level][hashIdx*uint64(hashSize):], hash)
		copy(currentHash, hash)

		copy(hashBlock[hashBlockPos:], hash)
		hashBlockPos += uint64(hashSize)
		if vh.params.HashType == 1 {
			hashBlockPos += uint64(digestSizeFull - hashSize)
		}
	}

	if !isLastLevel {
		offset := levels[level].offset + blockIdx*uint64(vh.params.HashBlockSize)
		if verify {
			if err := vh.verifyHashBlockData(hashFile, offset, hashBlock, hashBlockPos); err != nil {
				return fmt.Errorf("verification failed at level %d block %d: %w", level, blockIdx, err)
			}
		} else {
			if err := writeBlock(hashFile, offset, hashBlock); err != nil {
				return fmt.Errorf("failed to write hash block at level %d block %d: %w", level, blockIdx, err)
			}
		}
	}

	return nil
}

func (vh *VerityHash) getDigestSizeFull(hashSize uint32) uint32 {
	if vh.params.HashType == 0 {
		return hashSize
	}
	if hashSize == 0 {
		return 1
	}
	n := hashSize - 1
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	return n + 1
}

func (vh *VerityHash) verifyHashBlockData(hashFile *os.File, offset uint64, expectedBlock []byte, dataLen uint64) error {
	storedBlock, err := readBlock(hashFile, offset, vh.params.HashBlockSize)
	if err != nil {
		return fmt.Errorf("failed to read stored hash block: %w", err)
	}

	if !bytes.Equal(expectedBlock[:dataLen], storedBlock[:dataLen]) {
		return fmt.Errorf("hash block data mismatch")
	}

	for i := dataLen; i < uint64(vh.params.HashBlockSize); i++ {
		if storedBlock[i] != 0 {
			return fmt.Errorf("spare area is not zeroed at position %d", i)
		}
	}
	return nil
}

func (vh *VerityHash) finalizeRootHash(currentHash []byte, verify bool) error {
	if verify && !bytes.Equal(currentHash, vh.rootHash) {
		return fmt.Errorf("root hash verification failed")
	}
	if !verify {
		copy(vh.rootHash, currentHash)
	}
	return nil
}

func (vh *VerityHash) RootHash() []byte {
	out := make([]byte, len(vh.rootHash))
	copy(out, vh.rootHash)
	return out
}
