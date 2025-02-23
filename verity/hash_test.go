package verity

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// testCreateAndVerify tests the creation and verification process
func testCreateAndVerify(t *testing.T, params *VerityParams, dataPath, hashPath string) error {
	t.Helper()

	// Create hash
	vh := NewVerityHash(params, dataPath, hashPath, make([]byte, 32))
	if err := vh.Create(); err != nil {
		return fmt.Errorf("hash creation failed: %w", err)
	}

	// Save root hash
	rootHash := make([]byte, 32)
	copy(rootHash, vh.rootHash)

	// Verify hash
	vh = NewVerityHash(params, dataPath, hashPath, rootHash)
	if err := vh.Verify(); err != nil {
		return fmt.Errorf("hash verification failed: %w", err)
	}

	return nil
}

// TestVerityHash tests hash creation and verification
func TestVerityHash(t *testing.T) {
	tests := []struct {
		name     string
		dataSize uint64
		wantErr  bool
	}{
		{
			name:     "small file (1MB)",
			dataSize: 1024 * 1024,
			wantErr:  false,
		},
		{
			name:     "medium file (10MB)",
			dataSize: 10 * 1024 * 1024,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare temporary files
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			// Create test data and parameters
			setupTestData(t, dataPath, hashPath, tt.dataSize)
			params := setupVerityTestParams(tt.dataSize)

			// Test creation and verification
			if err := testCreateAndVerify(t, params, dataPath, hashPath); (err != nil) != tt.wantErr {
				t.Errorf("testCreateAndVerify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestVerityHashDataCorruption tests hash data corruption detection
func TestVerityHashDataCorruption(t *testing.T) {
	// Prepare test environment
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.img")
	hashPath := filepath.Join(tmpDir, "hash.img")
	dataSize := uint64(1024 * 1024) // 1MB

	setupTestData(t, dataPath, hashPath, dataSize)
	params := setupVerityTestParams(dataSize)

	// Create initial hash
	vh := NewVerityHash(params, dataPath, hashPath, make([]byte, 32))
	if err := vh.Create(); err != nil {
		t.Fatalf("Failed to create initial hash: %v", err)
	}

	// Save root hash
	rootHash := make([]byte, 32)
	copy(rootHash, vh.rootHash)

	// Modify data and verify failure
	f, err := os.OpenFile(dataPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("Failed to open data file: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteAt([]byte{0xFF}, 1000); err != nil {
		t.Fatalf("Failed to modify data: %v", err)
	}

	// Verification should fail
	vh = NewVerityHash(params, dataPath, hashPath, rootHash)
	if err := vh.Verify(); err == nil {
		t.Error("Verification should fail with corrupted data")
	}
}

// TestAgainstVeritySetup tests compatibility with veritysetup tool
func TestAgainstVeritySetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found in PATH")
	}

	tests := []struct {
		name     string
		dataSize uint64
	}{
		{"1MB file", 1024 * 1024},
		{"4MB file", 4 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			params := setupVerityTestParams(tt.dataSize)
			setupTestData(t, dataPath, hashPath, tt.dataSize)

			// Compare implementations
			if err := compareVerityImplementations(t, params, dataPath, hashPath); err != nil {
				t.Errorf("Implementation comparison failed: %v", err)
			}
		})
	}
}

// compareVerityImplementations compares our implementation with veritysetup
func compareVerityImplementations(t *testing.T, params *VerityParams, dataPath, hashPath string) error {
	// Prepare test data
	setupTestData(t, dataPath, hashPath, params.DataSize*uint64(params.DataBlockSize))

	// Use our implementation to generate hash
	ourVh := NewVerityHash(params, dataPath, hashPath, make([]byte, 32))
	if err := ourVh.Create(); err != nil {
		return fmt.Errorf("our implementation create failed: %w", err)
	}

	// Save our hash file content
	ourHashContent, err := readFileContent(hashPath)
	if err != nil {
		return fmt.Errorf("failed to read our hash file: %w", err)
	}

	// Use veritysetup to generate hash
	veritysetupHashPath := hashPath + ".verity"
	veritysetupRootHash, err := getVeritySetupRootHash(t, dataPath, hashPath, params)
	if err != nil {
		return fmt.Errorf("veritysetup failed: %w", err)
	}

	// Read veritysetup hash file content
	veritysetupHashContent, err := readFileContent(veritysetupHashPath)
	if err != nil {
		return fmt.Errorf("failed to read veritysetup hash file: %w", err)
	}

	// Compare root hash
	if !bytes.Equal(ourVh.rootHash, veritysetupRootHash) {
		return fmt.Errorf("root hash mismatch\nOur: %x\nVeritysetup: %x",
			ourVh.rootHash, veritysetupRootHash)
	}

	// Compare hash file content
	// Note: We only compare content from HashAreaOffset because veritysetup might have extra metadata at the beginning
	ourHashData := ourHashContent[params.HashAreaOffset:]
	veritysetupHashData := veritysetupHashContent[params.HashAreaOffset:]

	if !bytes.Equal(ourHashData, veritysetupHashData) {
		return fmt.Errorf("hash file content mismatch from offset %d\nOur hash len: %d\nVeritysetup hash len: %d",
			params.HashAreaOffset, len(ourHashData), len(veritysetupHashData))
	}

	return nil
}
