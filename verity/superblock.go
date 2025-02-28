package verity

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// NewSuperBlock creates a new verity superblock with default values
func NewSuperBlock() *VeritySuperblock {
	sb := &VeritySuperblock{}
	copy(sb.Signature[:], VeritySignature)
	sb.Version = 1
	sb.HashType = 1 // normal
	return sb
}

// Serialize converts the superblock to bytes
func (sb *VeritySuperblock) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, sb); err != nil {
		return nil, fmt.Errorf("failed to serialize superblock: %w", err)
	}
	return buf.Bytes(), nil
}

// Deserialize reads a superblock from bytes
func DeserializeSuperBlock(data []byte) (*VeritySuperblock, error) {
	if len(data) < VeritySuperblockSize {
		return nil, fmt.Errorf("data too short for superblock")
	}

	sb := &VeritySuperblock{}
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, sb); err != nil {
		return nil, fmt.Errorf("failed to deserialize superblock: %w", err)
	}

	// Verify signature
	if string(sb.Signature[:]) != VeritySignature {
		return nil, fmt.Errorf("invalid verity signature")
	}

	// Verify version
	if sb.Version != 1 {
		return nil, fmt.Errorf("unsupported verity version: %d", sb.Version)
	}

	return sb, nil
}
