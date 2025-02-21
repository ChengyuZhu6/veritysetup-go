package verity

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestVerityHash(t *testing.T) {
	// Create temp files
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data")
	hashPath := filepath.Join(tmpDir, "hash")

	// Create test data
	dataSize := uint64(1024 * 1024) // 1MB
	data := make([]byte, dataSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Write test data
	if err := os.WriteFile(dataPath, data, 0644); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	// Create empty hash file
	hashFile, err := os.Create(hashPath)
	if err != nil {
		t.Fatalf("Failed to create hash file: %v", err)
	}
	hashFile.Close()

	// Create verity params
	params := &VerityParams{
		HashName:      "sha256",
		DataBlockSize: 4096,
		HashBlockSize: 4096,
		DataSize:      dataSize / 4096,
		HashType:      1,
		Salt:          []byte("test salt"),
		SaltSize:      9,
	}

	// Create hash
	vh := NewVerityHash(params, dataPath, hashPath, make([]byte, 32))
	if err := vh.Create(); err != nil {
		t.Fatalf("Failed to create hash: %v", err)
	}

	// Save root hash
	rootHash := make([]byte, 32)
	copy(rootHash, vh.rootHash)

	// Verify hash
	vh = NewVerityHash(params, dataPath, hashPath, rootHash)
	if err := vh.Verify(); err != nil {
		t.Fatalf("Failed to verify hash: %v", err)
	}

	// Modify data and verify failure
	data[1000] ^= 0xFF
	if err := os.WriteFile(dataPath, data, 0644); err != nil {
		t.Fatalf("Failed to write modified data: %v", err)
	}

	if err := vh.Verify(); err == nil {
		t.Fatal("Verification should fail with modified data")
	}
}

func TestHashCreateVerify(t *testing.T) {
	// Create test devices
	dataDevice, err := createTestDevice(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to create test device: %v", err)
	}
	defer os.Remove(dataDevice)

	hashDevice, err := createTestDevice(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to create test device: %v", err)
	}
	defer os.Remove(hashDevice)

	// Create test params
	params := createTestParams()

	// Create hash
	vh := NewVerityHash(params, dataDevice, hashDevice, make([]byte, 32))
	if err := vh.Create(); err != nil {
		t.Fatalf("Failed to create hash: %v", err)
	}

	// Save root hash
	rootHash := make([]byte, 32)
	copy(rootHash, vh.rootHash)

	// Verify hash
	vh = NewVerityHash(params, dataDevice, hashDevice, rootHash)
	if err := vh.Verify(); err != nil {
		t.Fatalf("Failed to verify hash: %v", err)
	}

	// Modify data and verify failure
	f, err := os.OpenFile(dataDevice, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("Failed to open data device: %v", err)
	}
	f.WriteAt([]byte{0xFF}, 1000)
	f.Close()

	if err := vh.Verify(); err == nil {
		t.Fatal("Verification should fail with modified data")
	}
}

func TestHashWithDifferentSizes(t *testing.T) {
	sizes := []uint64{
		4096,     // 1 block
		8192,     // 2 blocks
		1048576,  // 256 blocks
		10485760, // 2560 blocks
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			// Create test devices
			dataDevice, err := createTestDevice(size)
			if err != nil {
				t.Fatalf("Failed to create test device: %v", err)
			}
			defer os.Remove(dataDevice)

			hashDevice, err := createTestDevice(size / 2) // Hash device can be smaller
			if err != nil {
				t.Fatalf("Failed to create test device: %v", err)
			}
			defer os.Remove(hashDevice)

			// Create test params
			params := createTestParams()
			params.DataSize = size / uint64(params.DataBlockSize)

			// Create and verify hash
			vh := NewVerityHash(params, dataDevice, hashDevice, make([]byte, 32))
			if err := vh.Create(); err != nil {
				t.Fatalf("Failed to create hash: %v", err)
			}

			rootHash := make([]byte, 32)
			copy(rootHash, vh.rootHash)

			vh = NewVerityHash(params, dataDevice, hashDevice, rootHash)
			if err := vh.Verify(); err != nil {
				t.Fatalf("Failed to verify hash: %v", err)
			}
		})
	}
}
