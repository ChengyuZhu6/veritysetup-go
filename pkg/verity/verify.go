package verity

import (
	"bytes"
	"fmt"
	"os"
)

// VerifyStrategy defines how aggressively to verify data
type VerifyStrategy int

const (
	// VerifyAlways verifies every access
	VerifyAlways VerifyStrategy = iota
	// VerifyAtMostOnce verifies a block once then caches the result
	VerifyAtMostOnce
)

// CorruptionError contains context about a detected corruption
type CorruptionError struct {
	BlockIndex uint64
	Message    string
}

func (e *CorruptionError) Error() string {
	return fmt.Sprintf("corruption at block %d: %s", e.BlockIndex, e.Message)
}

// Verifier implements user-space verification against the stored hash tree and root digest
type Verifier struct {
	vh       *VerityHash
	strategy VerifyStrategy
	verified map[uint64]struct{}
	dataFile *os.File
	hashFile *os.File
}

func NewVerifier(params *VerityParams, dataPath, hashPath string, rootDigest []byte, strategy VerifyStrategy) (*Verifier, error) {
	vh := NewVerityHash(params, dataPath, hashPath, rootDigest)
	dataFile, hashFile, err := vh.openDeviceFiles(true)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		vh:       vh,
		strategy: strategy,
		verified: make(map[uint64]struct{}),
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
	return v.vh.Verify()
}

func (v *Verifier) VerifyRange(offset, length uint64) error {
	if length == 0 {
		return nil
	}
	bs := uint64(v.vh.params.DataBlockSize)
	start := offset / bs
	end := (offset + length + bs - 1) / bs
	if end > v.vh.params.DataBlocks {
		end = v.vh.params.DataBlocks
	}
	for i := start; i < end; i++ {
		if err := v.VerifyBlock(i); err != nil {
			return err
		}
	}
	return nil
}

func (v *Verifier) VerifyBlock(blockIndex uint64) error {
	if v.strategy == VerifyAtMostOnce {
		if _, ok := v.verified[blockIndex]; ok {
			return nil
		}
	}

	data, err := readBlock(v.dataFile, blockIndex*uint64(v.vh.params.DataBlockSize), v.vh.params.DataBlockSize)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}
	leaf, err := v.vh.verifyHashBlock(data, v.vh.params.Salt)
	if err != nil {
		return fmt.Errorf("compute leaf: %w", err)
	}

	// With root-first layout, leaves are at levels[0].offset
	levels, err := v.vh.calculateHashLevels()
	if err != nil {
		return err
	}
	leafBase := levels[0].offset
	hashSize := uint32(v.vh.hashFunc.Size())
	hashesPerBlock := v.vh.params.HashBlockSize / hashSize
	blockIdx := blockIndex / uint64(hashesPerBlock)
	intra := (blockIndex % uint64(hashesPerBlock)) * uint64(hashSize)
	offset := leafBase + blockIdx*uint64(v.vh.params.HashBlockSize) + intra
	stored, err := readBlock(v.hashFile, offset, hashSize)
	if err != nil {
		return fmt.Errorf("read stored leaf: %w", err)
	}

	if len(stored) != len(leaf) || !bytes.Equal(stored, leaf) {
		return &CorruptionError{BlockIndex: blockIndex, Message: "leaf mismatch"}
	}

	if err := v.verifyPathAcrossLevels(blockIndex); err != nil {
		return err
	}

	if v.strategy == VerifyAtMostOnce {
		v.verified[blockIndex] = struct{}{}
	}
	return nil
}

func (v *Verifier) verifyPathAcrossLevels(leafIndex uint64) error {
	levels, err := v.vh.calculateHashLevels()
	if err != nil {
		return err
	}
	if len(levels) < 2 {
		return nil
	}

	hashSize := uint32(v.vh.hashFunc.Size())
	hashesPerBlock := v.vh.params.HashBlockSize / hashSize
	currentIndex := leafIndex
	var lastComputed []byte

	for level := 0; level < len(levels)-1; level++ {
		childBlockIndex := currentIndex / uint64(hashesPerBlock)
		childBlockOffset := levels[level].offset + childBlockIndex*uint64(v.vh.params.HashBlockSize)
		childBlockBytes, err := readBlock(v.hashFile, childBlockOffset, v.vh.params.HashBlockSize)
		if err != nil {
			return fmt.Errorf("read child block at level %d: %w", level, err)
		}
		computedParent, err := v.vh.verifyHashBlock(childBlockBytes, v.vh.params.Salt)
		if err != nil {
			return fmt.Errorf("compute parent at level %d: %w", level, err)
		}

		parentIndex := childBlockIndex
		// Root digest is not stored in hash area; skip on last level
		if level+1 < len(levels)-1 {
			parentBlockIndex := parentIndex / uint64(hashesPerBlock)
			intra := (parentIndex % uint64(hashesPerBlock)) * uint64(hashSize)
			parentOffset := levels[level+1].offset + parentBlockIndex*uint64(v.vh.params.HashBlockSize) + intra
			storedParent, err := readBlock(v.hashFile, parentOffset, hashSize)
			if err != nil {
				return fmt.Errorf("read stored parent at level %d: %w", level+1, err)
			}
			if !bytes.Equal(storedParent, computedParent) {
				return fmt.Errorf("parent mismatch at level %d index %d", level+1, parentIndex)
			}
		}

		lastComputed = computedParent
		currentIndex = parentIndex
	}

	if !bytes.Equal(lastComputed, v.vh.rootHash) {
		return fmt.Errorf("root digest mismatch")
	}
	return nil
}
