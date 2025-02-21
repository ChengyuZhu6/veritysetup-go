package verity

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"log"
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
	vh := &VerityHash{
		params:     params,
		dataDevice: dataDevice,
		hashDevice: hashDevice,
		rootHash:   make([]byte, 32),
	}
	// 确保正确复制根哈希
	if rootHash != nil {
		copy(vh.rootHash, rootHash)
	}
	return vh
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
	hashPerBlock := vh.params.HashBlockSize / 32 // SHA256 hash size is 32 bytes
	levels := make([]hashTreeLevel, 0)

	blocks := vh.params.DataSize
	offset := vh.params.HashAreaOffset

	// First level starts at the offset
	hashOffset := offset

	// Calculate each level from bottom up
	for blocks > 1 {
		level := hashTreeLevel{
			offset: hashOffset,
			size:   blocks,
		}
		levels = append(levels, level) // Append level

		// Calculate next level
		blocks = (blocks + uint64(hashPerBlock) - 1) / uint64(hashPerBlock)
		hashOffset += blocks * uint64(vh.params.HashBlockSize)
	}

	// Add root level
	levels = append(levels, hashTreeLevel{
		offset: hashOffset,
		size:   1,
	})

	return levels, nil
}

// verifyHashBlock verifies a single hash block
func (vh *VerityHash) verifyHashBlock(data []byte, salt []byte) ([]byte, error) {
	h := crypto.SHA256.New()

	// 确保按照正确的顺序添加salt和data
	if vh.params.HashType == 1 {
		// 先写入salt，再写入data
		if len(salt) > 0 {
			h.Write(salt)
		}
		h.Write(data)
	} else {
		// 先写入data，再写入salt
		h.Write(data)
		if len(salt) > 0 {
			h.Write(salt)
		}
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
	// 打开设备文件
	dataFile, hashFile, err := vh.openDeviceFiles(verify)
	if err != nil {
		return fmt.Errorf("failed to open device files: %w", err)
	}
	defer dataFile.Close()
	defer hashFile.Close()

	// 计算哈希树层级
	levels, err := vh.calculateHashLevels()
	if err != nil {
		return fmt.Errorf("failed to calculate hash levels: %w", err)
	}

	if len(levels) > VerityMaxLevels {
		return fmt.Errorf("hash tree exceeds maximum levels: %d", len(levels))
	}

	// 创建哈希缓冲区
	hashBuffers := vh.createHashBuffers(levels)

	// 处理每一层哈希
	currentHash, err := vh.processHashLevels(levels, hashBuffers, dataFile, hashFile, verify)
	if err != nil {
		return err
	}

	// 验证或保存根哈希
	return vh.finalizeRootHash(currentHash, verify)
}

// openDeviceFiles 打开数据和哈希设备文件
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

// createHashBuffers 为每一层创建哈希缓冲区
func (vh *VerityHash) createHashBuffers(levels []hashTreeLevel) [][]byte {
	hashBuffers := make([][]byte, len(levels))
	for i := range hashBuffers {
		hashBuffers[i] = make([]byte, levels[i].size*32)
	}
	return hashBuffers
}

// processHashLevels 处理所有哈希层级
func (vh *VerityHash) processHashLevels(levels []hashTreeLevel, hashBuffers [][]byte,
	dataFile, hashFile *os.File, verify bool) ([]byte, error) {

	hashPerBlock := vh.params.HashBlockSize / 32
	currentHash := make([]byte, 32)

	for i := 0; i < len(levels); i++ {
		for j := uint64(0); j < levels[i].size; j++ {
			blockData, err := vh.readBlockData(i, j, hashPerBlock, levels, hashBuffers, dataFile)
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

		// 写入哈希文件
		if !verify && i == 0 {
			// 注意：写入时不需要加上HashAreaOffset，因为levels[i].offset已经包含了这个偏移
			if err := writeBlock(hashFile, levels[i].offset, hashBuffers[i]); err != nil {
				return nil, fmt.Errorf("failed to write hash level: %w", err)
			}
		}
	}

	return currentHash, nil
}

// readBlockData 读取指定层级和块的数据
func (vh *VerityHash) readBlockData(level int, blockNum uint64, hashPerBlock uint32,
	levels []hashTreeLevel, hashBuffers [][]byte, dataFile *os.File) ([]byte, error) {

	if level == 0 {
		return readBlock(dataFile, blockNum*uint64(vh.params.DataBlockSize), vh.params.DataBlockSize)
	}

	blockStart := blockNum * uint64(hashPerBlock)
	blockEnd := blockStart + uint64(hashPerBlock)
	if blockEnd > levels[level-1].size {
		blockEnd = levels[level-1].size
	}

	blockData := make([]byte, vh.params.HashBlockSize)
	copy(blockData, hashBuffers[level-1][blockStart*32:blockEnd*32])
	return blockData, nil
}

// handleHashResult 处理哈希计算结果
func (vh *VerityHash) handleHashResult(level int, blockNum uint64, hash []byte,
	hashBuffers [][]byte, hashFile *os.File, levels []hashTreeLevel, verify bool) error {

	if verify {
		if level == 0 {
			// 对于level 0，需要与hash file中存储的哈希比较
			// 注意：读取时不需要重复加上HashAreaOffset，因为levels[level].offset已经包含了这个偏移
			offset := levels[level].offset + blockNum*32

			storedHash, err := readBlock(hashFile, offset, 32)
			if err != nil {
				return fmt.Errorf("failed to read stored hash at level %d block %d: %w", level, blockNum, err)
			}

			if !bytes.Equal(hash, storedHash) {
				return fmt.Errorf("hash mismatch at level %d block %d", level, blockNum)
			}
		}
	}

	// 保存哈希到缓冲区
	copy(hashBuffers[level][blockNum*32:], hash)

	return nil
}

// finalizeRootHash 验证或保存根哈希
func (vh *VerityHash) finalizeRootHash(currentHash []byte, verify bool) error {
	log.Printf("currentHash: %x", currentHash)
	log.Printf("rootHash: %x", vh.rootHash)
	if verify {
		if !bytes.Equal(currentHash, vh.rootHash) {
			return fmt.Errorf("root hash verification failed")
		}
		return nil
	}

	copy(vh.rootHash, currentHash)
	return nil
}
