package verity

import (
	"os"
	"testing"
)

func TestSuperblockReadWrite(t *testing.T) {
	// Create test devices
	dataDevice, err := createTestDevice(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to create test device: %v", err)
	}
	defer os.Remove(dataDevice)

	// Create test params
	params := createTestParams()
	uuid := "12345678-1234-5678-1234-567812345678"

	// Write superblock
	if err := WriteSuperblock(dataDevice, 0, uuid, params); err != nil {
		t.Fatalf("Failed to write superblock: %v", err)
	}

	// Read and verify superblock
	readParams, readUUID, err := ReadSuperblock(dataDevice, 0)
	if err != nil {
		t.Fatalf("Failed to read superblock: %v", err)
	}

	// Verify params
	if readParams.HashName != params.HashName {
		t.Errorf("HashName mismatch: got %s, want %s", readParams.HashName, params.HashName)
	}
	if readParams.DataBlockSize != params.DataBlockSize {
		t.Errorf("DataBlockSize mismatch: got %d, want %d", readParams.DataBlockSize, params.DataBlockSize)
	}
	if readParams.HashBlockSize != params.HashBlockSize {
		t.Errorf("HashBlockSize mismatch: got %d, want %d", readParams.HashBlockSize, params.HashBlockSize)
	}
	if readParams.DataSize != params.DataSize {
		t.Errorf("DataSize mismatch: got %d, want %d", readParams.DataSize, params.DataSize)
	}
	if readParams.HashType != params.HashType {
		t.Errorf("HashType mismatch: got %d, want %d", readParams.HashType, params.HashType)
	}
	if string(readParams.Salt) != string(params.Salt) {
		t.Errorf("Salt mismatch: got %x, want %x", readParams.Salt, params.Salt)
	}

	// Verify UUID
	if readUUID != uuid {
		t.Errorf("UUID mismatch: got %s, want %s", readUUID, uuid)
	}
}
