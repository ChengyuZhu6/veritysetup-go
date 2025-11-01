package verity

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	VeritySignature      = "verity\x00\x00"
	VeritySuperblockSize = 512
	VerityMaxHashType    = 1
	VerityMaxLevels      = 63
	VerityMaxDigestSize  = 1024
	MaxSaltSize          = 256
)

// VeritySuperblock represents the on-disk superblock format
type VeritySuperblock struct {
	Signature     [8]byte
	Version       uint32
	HashType      uint32
	UUID          [16]byte
	Algorithm     [32]byte
	DataBlockSize uint32
	HashBlockSize uint32
	DataBlocks    uint64
	SaltSize      uint16
	Pad1          [6]byte
	Salt          [256]byte
	Pad2          [168]byte
}

// DefaultVeritySuperblock returns a VeritySuperblock with default values
func DefaultVeritySuperblock() VeritySuperblock {
	return VeritySuperblock{
		Signature:     [8]byte{0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x00, 0x00},
		Version:       1,
		HashType:      1,
		DataBlockSize: 4096,
		HashBlockSize: 4096,
		Algorithm:     [32]byte{0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
}

// NewSuperblock creates a new VeritySuperblock with signature and defaults.
func NewSuperblock() *VeritySuperblock {
	sb := &VeritySuperblock{}
	copy(sb.Signature[:], VeritySignature)
	sb.Version = 1
	sb.HashType = 1 // normal
	return sb
}

// Serialize serializes the superblock into a little-endian byte slice of size VeritySuperblockSize.
func (sb *VeritySuperblock) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, sb); err != nil {
		return nil, fmt.Errorf("failed to serialize superblock: %w", err)
	}
	return buf.Bytes(), nil
}

// DeserializeSuperblock parses a VeritySuperblock from a little-endian byte slice.
func DeserializeSuperblock(data []byte) (*VeritySuperblock, error) {
	if len(data) < VeritySuperblockSize {
		return nil, fmt.Errorf("data too short for superblock")
	}

	sb := &VeritySuperblock{}
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, sb); err != nil {
		return nil, fmt.Errorf("failed to deserialize superblock: %w", err)
	}

	if string(sb.Signature[:]) != VeritySignature {
		return nil, fmt.Errorf("invalid verity signature")
	}
	if sb.Version != 1 {
		return nil, fmt.Errorf("unsupported verity version: %d", sb.Version)
	}

	return sb, nil
}

// alignUp returns x aligned up to the next multiple of align (align must be power of two or positive divisor).
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

func buildSuperblockFromParams(p *VerityParams) (*VeritySuperblock, error) {
	if !IsBlockSizeValid(p.DataBlockSize) || !IsBlockSizeValid(p.HashBlockSize) {
		return nil, fmt.Errorf("invalid block sizes: data %d hash %d", p.DataBlockSize, p.HashBlockSize)
	}
	if p.SaltSize != uint16(len(p.Salt)) {
		return nil, fmt.Errorf("salt size mismatch: declared %d actual %d", p.SaltSize, len(p.Salt))
	}
	if p.SaltSize > MaxSaltSize {
		return nil, fmt.Errorf("salt too large: %d > %d", p.SaltSize, MaxSaltSize)
	}
	algo := strings.ToLower(p.HashName)
	sb := DefaultVeritySuperblock()
	sb.HashType = p.HashType
	sb.DataBlockSize = p.DataBlockSize
	sb.HashBlockSize = p.HashBlockSize
	sb.DataBlocks = p.DataBlocks
	sb.SaltSize = p.SaltSize
	copy(sb.Salt[:], p.Salt)
	sb.UUID = p.UUID
	// write algorithm name as lower-case, null-padded
	for i := range sb.Algorithm {
		sb.Algorithm[i] = 0
	}
	copy(sb.Algorithm[:], []byte(algo))
	return &sb, nil
}

func validateAndAdoptSuperblock(p *VerityParams, sb *VeritySuperblock) error {
	if string(sb.Signature[:]) != VeritySignature {
		return fmt.Errorf("invalid verity signature")
	}
	if sb.Version != 1 {
		return fmt.Errorf("unsupported verity version: %d", sb.Version)
	}
	if sb.HashType > VerityMaxHashType {
		return fmt.Errorf("unsupported hash type: %d", sb.HashType)
	}
	if !IsBlockSizeValid(sb.DataBlockSize) || !IsBlockSizeValid(sb.HashBlockSize) {
		return fmt.Errorf("invalid block size in superblock: data %d hash %d", sb.DataBlockSize, sb.HashBlockSize)
	}
	if sb.SaltSize > MaxSaltSize {
		return fmt.Errorf("superblock salt too large: %d", sb.SaltSize)
	}
	// Algorithm must match params (lower-case). If params empty, adopt from superblock.
	algo := strings.TrimRight(string(sb.Algorithm[:]), "\x00")
	algo = strings.ToLower(algo)
	if p.HashName == "" {
		p.HashName = algo
	}
	if strings.ToLower(p.HashName) != algo {
		return fmt.Errorf("algorithm mismatch: param %s superblock %s", p.HashName, algo)
	}
	if p.DataBlockSize == 0 {
		p.DataBlockSize = sb.DataBlockSize
	} else if p.DataBlockSize != sb.DataBlockSize {
		return fmt.Errorf("data block size mismatch: param %d sb %d", p.DataBlockSize, sb.DataBlockSize)
	}
	if p.HashBlockSize == 0 {
		p.HashBlockSize = sb.HashBlockSize
	} else if p.HashBlockSize != sb.HashBlockSize {
		return fmt.Errorf("hash block size mismatch: param %d sb %d", p.HashBlockSize, sb.HashBlockSize)
	}
	if p.DataBlocks == 0 {
		p.DataBlocks = sb.DataBlocks
	} else if p.DataBlocks != sb.DataBlocks {
		return fmt.Errorf("data blocks mismatch: param %d sb %d", p.DataBlocks, sb.DataBlocks)
	}
	if len(p.Salt) == 0 {
		p.Salt = make([]byte, sb.SaltSize)
		copy(p.Salt, sb.Salt[:sb.SaltSize])
		p.SaltSize = sb.SaltSize
	} else {
		if p.SaltSize != sb.SaltSize || !bytes.Equal(p.Salt, sb.Salt[:sb.SaltSize]) {
			return fmt.Errorf("salt mismatch")
		}
	}
	if p.UUID == ([16]byte{}) {
		p.UUID = sb.UUID
	} else if p.UUID != sb.UUID {
		return fmt.Errorf("UUID mismatch")
	}
	p.HashAreaOffset = alignUp(VeritySuperblockSize, uint64(p.HashBlockSize))
	return nil
}

// AdoptParamsFromSuperblock validates the provided superblock and populates
// the given VerityParams with values derived from it (algorithm, block sizes,
// data blocks, salt, UUID, and HashAreaOffset). Returns error if incompatible.
func AdoptParamsFromSuperblock(p *VerityParams, sb *VeritySuperblock) error {
	return validateAndAdoptSuperblock(p, sb)
}
