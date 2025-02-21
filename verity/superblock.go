package verity

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

// ReadSuperblock reads verity superblock from device
func ReadSuperblock(device string, offset uint64) (*VerityParams, string, error) {
	f, err := os.OpenFile(device, os.O_RDONLY, 0)
	if err != nil {
		return nil, "", fmt.Errorf("cannot open device %s: %v", device, err)
	}
	defer f.Close()

	// Seek to superblock offset
	if _, err := f.Seek(int64(offset), 0); err != nil {
		return nil, "", fmt.Errorf("cannot seek to superblock: %v", err)
	}

	var sb VeritySuperblock
	if err := binary.Read(f, binary.LittleEndian, &sb); err != nil {
		return nil, "", fmt.Errorf("cannot read superblock: %v", err)
	}

	// Verify signature
	if !bytes.Equal(sb.Signature[:], []byte(VeritySignature)) {
		return nil, "", fmt.Errorf("invalid verity signature")
	}

	// Verify version
	if sb.Version != 1 {
		return nil, "", fmt.Errorf("unsupported verity version %d", sb.Version)
	}

	// Verify hash type
	if sb.HashType > VerityMaxHashType {
		return nil, "", fmt.Errorf("unsupported hash type %d", sb.HashType)
	}

	// Create UUID string
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		sb.UUID[0:4], sb.UUID[4:6], sb.UUID[6:8], sb.UUID[8:10], sb.UUID[10:])

	params := &VerityParams{
		HashName:       string(bytes.TrimRight(sb.Algorithm[:], "\x00")),
		DataBlockSize:  sb.DataBlockSize,
		HashBlockSize:  sb.HashBlockSize,
		DataSize:       sb.DataBlocks,
		HashType:       sb.HashType,
		Salt:           make([]byte, sb.SaltSize),
		SaltSize:       sb.SaltSize,
		HashAreaOffset: offset,
	}

	copy(params.Salt, sb.Salt[:sb.SaltSize])

	return params, uuid, nil
}

// WriteSuperblock writes verity superblock to device
func WriteSuperblock(device string, offset uint64, uuid string, params *VerityParams) error {
	f, err := os.OpenFile(device, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot open device %s: %v", device, err)
	}
	defer f.Close()

	var sb VeritySuperblock
	copy(sb.Signature[:], []byte(VeritySignature))
	sb.Version = 1
	sb.HashType = params.HashType
	sb.DataBlockSize = params.DataBlockSize
	sb.HashBlockSize = params.HashBlockSize
	sb.DataBlocks = params.DataSize
	sb.SaltSize = params.SaltSize
	copy(sb.Algorithm[:], []byte(params.HashName))
	copy(sb.Salt[:], params.Salt)

	// Parse UUID into bytes
	if _, err := fmt.Sscanf(uuid,
		"%2x%2x%2x%2x-%2x%2x-%2x%2x-%2x%2x-%2x%2x%2x%2x%2x%2x",
		&sb.UUID[0], &sb.UUID[1], &sb.UUID[2], &sb.UUID[3],
		&sb.UUID[4], &sb.UUID[5], &sb.UUID[6], &sb.UUID[7],
		&sb.UUID[8], &sb.UUID[9], &sb.UUID[10], &sb.UUID[11],
		&sb.UUID[12], &sb.UUID[13], &sb.UUID[14], &sb.UUID[15]); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}

	// Seek to superblock offset
	if _, err := f.Seek(int64(offset), 0); err != nil {
		return fmt.Errorf("cannot seek to superblock: %v", err)
	}

	// Write superblock
	if err := binary.Write(f, binary.LittleEndian, &sb); err != nil {
		return fmt.Errorf("cannot write superblock: %v", err)
	}

	return nil
}
