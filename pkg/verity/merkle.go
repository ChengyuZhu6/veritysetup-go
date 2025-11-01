package verity

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"io"
	"os"
)

type VerityHash struct {
	hashName       string
	dataBlockSize  uint32
	hashBlockSize  uint32
	dataBlocks     uint64
	hashType       uint32
	salt           []byte
	hashAreaOffset uint64
	dataDevice     string
	hashDevice     string
	rootHash       []byte
	hashFunc       crypto.Hash
}

type hashTreeLevel struct {
	offset    uint64
	numHashes uint64
	numBlocks uint64
}

func NewVerityHash(
	hashName string,
	dataBlockSize, hashBlockSize uint32,
	dataBlocks uint64,
	hashType uint32,
	salt []byte,
	hashAreaOffset uint64,
	dataDevice, hashDevice string,
	rootHash []byte,
) *VerityHash {
	hashMap := map[string]crypto.Hash{
		"sha256": crypto.SHA256,
		"sha512": crypto.SHA512,
		"sha1":   crypto.SHA1,
	}

	hashFunc := crypto.SHA256
	if h, ok := hashMap[hashName]; ok && h.Available() {
		hashFunc = h
	}

	vh := &VerityHash{
		hashName:       hashName,
		dataBlockSize:  dataBlockSize,
		hashBlockSize:  hashBlockSize,
		dataBlocks:     dataBlocks,
		hashType:       hashType,
		salt:           salt,
		hashAreaOffset: hashAreaOffset,
		dataDevice:     dataDevice,
		hashDevice:     hashDevice,
		rootHash:       make([]byte, hashFunc.Size()),
		hashFunc:       hashFunc,
	}
	if rootHash != nil {
		copy(vh.rootHash, rootHash)
	}
	return vh
}

func (vh *VerityHash) RootHash() []byte {
	out := make([]byte, len(vh.rootHash))
	copy(out, vh.rootHash)
	return out
}

func getBitsUp(u uint32) uint {
	var i uint
	for (1 << i) < u {
		i++
	}
	return i
}

func getBitsDown(u uint32) uint {
	var i uint
	for (u >> i) > 1 {
		i++
	}
	return i
}

func (vh *VerityHash) hashLevels(dataFileBlocks uint64) ([]hashTreeLevel, error) {
	digestSize := uint32(vh.hashFunc.Size())
	if digestSize == 0 {
		return nil, fmt.Errorf("invalid digest size")
	}

	hashPerBlockBits := getBitsDown(vh.hashBlockSize / digestSize)
	if hashPerBlockBits == 0 {
		return nil, fmt.Errorf("hash block size too small for digest")
	}

	numLevels := 0
	for hashPerBlockBits*uint(numLevels) < 64 &&
		((dataFileBlocks-1)>>(hashPerBlockBits*uint(numLevels))) > 0 {
		numLevels++
	}

	if numLevels > VerityMaxLevels {
		return nil, fmt.Errorf("hash tree exceeds maximum levels: %d", numLevels)
	}

	levels := make([]hashTreeLevel, numLevels)
	hashPosition := vh.hashAreaOffset / uint64(vh.hashBlockSize)

	for i := numLevels - 1; i >= 0; i-- {
		levels[i].offset = hashPosition * uint64(vh.hashBlockSize)

		sShift := uint((i + 1) * int(hashPerBlockBits))
		if sShift > 63 {
			return nil, fmt.Errorf("shift overflow at level %d", i)
		}
		s := (dataFileBlocks + (1 << sShift) - 1) >> sShift
		levels[i].numBlocks = s
		levels[i].numHashes = dataFileBlocks

		if hashPosition+s < hashPosition {
			return nil, fmt.Errorf("hash position overflow")
		}
		hashPosition += s
	}

	return levels, nil
}

func (vh *VerityHash) verifyHashBlock(data, salt []byte) ([]byte, error) {
	h := vh.hashFunc.New()

	if vh.hashType == 1 {
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

func verifyZero(block []byte, offset uint64) error {
	for i, b := range block {
		if b != 0 {
			return fmt.Errorf("spare area is not zeroed at position %d", offset+uint64(i))
		}
	}
	return nil
}

func (vh *VerityHash) getDigestSizeFull(hashSize uint32) uint32 {
	if vh.hashType == 0 {
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

func (vh *VerityHash) createOrVerify(
	rd, wr *os.File,
	dataBlock uint64, dataBlockSize uint32,
	hashBlock uint64, hashBlockSize uint32,
	blocks uint64,
	verify bool,
	calculatedDigest []byte,
) error {
	digestSize := uint32(vh.hashFunc.Size())
	if digestSize > VerityMaxDigestSize {
		return fmt.Errorf("digest size exceeds maximum")
	}

	digestSizeFull := vh.getDigestSizeFull(digestSize)
	hashPerBlock := uint32(1 << getBitsDown(hashBlockSize/digestSizeFull))
	blocksToWrite := (blocks + uint64(hashPerBlock) - 1) / uint64(hashPerBlock)

	seekRd := dataBlock * uint64(dataBlockSize)
	if _, err := rd.Seek(int64(seekRd), io.SeekStart); err != nil {
		return fmt.Errorf("cannot seek data device: %w", err)
	}

	if wr != nil {
		seekWr := hashBlock * uint64(hashBlockSize)
		if _, err := wr.Seek(int64(seekWr), io.SeekStart); err != nil {
			return fmt.Errorf("cannot seek hash device: %w", err)
		}
	}

	leftBlock := make([]byte, hashBlockSize)
	dataBuffer := make([]byte, dataBlockSize)

	for blocksToWrite > 0 {
		blocksToWrite--
		leftBytes := hashBlockSize

		for i := uint32(0); i < hashPerBlock; i++ {
			if blocks == 0 {
				break
			}
			blocks--

			if _, err := io.ReadFull(rd, dataBuffer); err != nil {
				return fmt.Errorf("cannot read data block: %w", err)
			}

			hash, err := vh.verifyHashBlock(dataBuffer, vh.salt)
			if err != nil {
				return fmt.Errorf("hash calculation failed: %w", err)
			}
			copy(calculatedDigest, hash)

			if wr == nil {
				break
			}

			if verify {
				readDigest := make([]byte, digestSize)
				if _, err := io.ReadFull(wr, readDigest); err != nil {
					return fmt.Errorf("cannot read digest from hash device: %w", err)
				}
				if !bytesEqual(readDigest, calculatedDigest[:digestSize]) {
					return fmt.Errorf("verification failed at data position %d", seekRd)
				}
			} else {
				if _, err := wr.Write(calculatedDigest[:digestSize]); err != nil {
					return fmt.Errorf("cannot write digest to hash device: %w", err)
				}
			}

			if vh.hashType == 0 {
				leftBytes -= digestSize
			} else {
				padding := digestSizeFull - digestSize
				if padding > 0 {
					if verify {
						padBuf := make([]byte, padding)
						if _, err := io.ReadFull(wr, padBuf); err != nil {
							return fmt.Errorf("cannot read padding: %w", err)
						}
						if err := verifyZero(padBuf, seekRd); err != nil {
							return err
						}
					} else {
						if _, err := wr.Write(leftBlock[:padding]); err != nil {
							return fmt.Errorf("cannot write padding: %w", err)
						}
					}
				}
				leftBytes -= digestSizeFull
			}
		}

		if wr != nil && leftBytes > 0 {
			if verify {
				spareBuf := make([]byte, leftBytes)
				if _, err := io.ReadFull(wr, spareBuf); err != nil {
					return fmt.Errorf("cannot read spare area: %w", err)
				}
				if err := verifyZero(spareBuf, seekRd); err != nil {
					return err
				}
			} else {
				if _, err := wr.Write(leftBlock[:leftBytes]); err != nil {
					return fmt.Errorf("cannot write spare area: %w", err)
				}
			}
		}
	}

	return nil
}

func (vh *VerityHash) createOrVerifyHashTree(verify bool) error {
	digestSize := uint32(vh.hashFunc.Size())
	if digestSize > VerityMaxDigestSize {
		return fmt.Errorf("digest size exceeds maximum")
	}

	dataFileBlocks := vh.dataBlocks

	levels, err := vh.hashLevels(dataFileBlocks)
	if err != nil {
		return fmt.Errorf("failed to calculate hash levels: %w", err)
	}

	dataFile, err := os.Open(vh.dataDevice)
	if err != nil {
		return fmt.Errorf("cannot open data device %s: %w", vh.dataDevice, err)
	}
	defer dataFile.Close()

	hashFile, err := os.OpenFile(vh.hashDevice, os.O_RDWR, 0)
	if verify {
		hashFile, err = os.Open(vh.hashDevice)
	}
	if err != nil {
		return fmt.Errorf("cannot open hash device %s: %w", vh.hashDevice, err)
	}
	defer hashFile.Close()

	calculatedDigest := make([]byte, digestSize)

	for i := 0; i < len(levels); i++ {
		var rd, wr *os.File
		var dataBlock, hashBlock uint64
		var dataBlockSize, hashBlockSize uint32
		var blocks uint64

		if i == 0 {
			rd = dataFile
			wr = hashFile
			dataBlock = 0
			dataBlockSize = vh.dataBlockSize
			hashBlock = levels[i].offset / uint64(vh.hashBlockSize)
			hashBlockSize = vh.hashBlockSize
			blocks = dataFileBlocks
		} else {
			hashFile2, err := os.Open(vh.hashDevice)
			if err != nil {
				return fmt.Errorf("cannot open hash device for reading: %w", err)
			}
			rd = hashFile2
			wr = hashFile
			dataBlock = levels[i-1].offset / uint64(vh.hashBlockSize)
			dataBlockSize = vh.hashBlockSize
			hashBlock = levels[i].offset / uint64(vh.hashBlockSize)
			hashBlockSize = vh.hashBlockSize
			blocks = levels[i-1].numBlocks

			err = vh.createOrVerify(rd, wr, dataBlock, dataBlockSize, hashBlock, hashBlockSize, blocks, verify, calculatedDigest)
			hashFile2.Close()
			if err != nil {
				return err
			}
			continue
		}

		if err := vh.createOrVerify(rd, wr, dataBlock, dataBlockSize, hashBlock, hashBlockSize, blocks, verify, calculatedDigest); err != nil {
			return err
		}
	}

	if len(levels) > 0 {
		lastLevel := levels[len(levels)-1]
		hashFile2, err := os.Open(vh.hashDevice)
		if err != nil {
			return fmt.Errorf("cannot open hash device for root: %w", err)
		}
		defer hashFile2.Close()

		err = vh.createOrVerify(
			hashFile2, nil,
			lastLevel.offset/uint64(vh.hashBlockSize), vh.hashBlockSize,
			0, vh.hashBlockSize,
			1, verify, calculatedDigest,
		)
		if err != nil {
			return err
		}
	} else {
		err = vh.createOrVerify(
			dataFile, nil,
			0, vh.dataBlockSize,
			0, vh.hashBlockSize,
			dataFileBlocks, verify, calculatedDigest,
		)
		if err != nil {
			return err
		}
	}

	if verify {
		if !bytesEqual(vh.rootHash, calculatedDigest[:digestSize]) {
			return fmt.Errorf("root hash verification failed")
		}
	} else {
		copy(vh.rootHash, calculatedDigest[:digestSize])
	}

	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
