package verity

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
)

// testCreateAndVerify tests the creation and verification process
func testCreateAndVerify(t *testing.T, params *VerityParams, dataPath, hashPath string) error {
	t.Helper()

	// Create hash with correct hash size
	vh := NewVerityHash(params, dataPath, hashPath, nil)
	rootHash := make([]byte, vh.hashFunc.Size())
	if err := vh.Create(); err != nil {
		return fmt.Errorf("hash creation failed: %w", err)
	}

	// Save root hash
	copy(rootHash, vh.rootHash)

	// Verify hash
	vh = NewVerityHash(params, dataPath, hashPath, rootHash)
	if err := vh.Verify(); err != nil {
		return fmt.Errorf("hash verification failed: %w", err)
	}
	return nil
}

// TestVerityHash tests hash creation and verification with different file sizes
func TestVerityHash(t *testing.T) {
	tests := []struct {
		name     string
		dataSize uint64
		params   *VerityParams
		wantErr  bool
	}{
		{
			name:     "small file (1MB)",
			dataSize: 1 * 1024 * 1024,
			params:   setupVerityTestParams(1 * 1024 * 1024),
			wantErr:  false,
		},
		{
			name:     "medium file (10MB)",
			dataSize: 10 * 1024 * 1024,
			params:   setupVerityTestParams(10 * 1024 * 1024),
			wantErr:  false,
		},
		{
			name:     "SHA512 with 4K blocks",
			dataSize: 1 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha512",
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataSize:       (1 * 1024 * 1024) / 4096,
				HashType:       1,
				Salt:           []byte("test-salt"),
				SaltSize:       uint16(len([]byte("test-salt"))),
				HashAreaOffset: 4096,
			},
			wantErr: false,
		},
		{
			name:     "SHA256 with 1K blocks",
			dataSize: 1 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha256",
				DataBlockSize:  1024,
				HashBlockSize:  1024,
				DataSize:       (1 * 1024 * 1024) / 1024,
				HashType:       1,
				Salt:           []byte("test-salt"),
				SaltSize:       uint16(len([]byte("test-salt"))),
				HashAreaOffset: 4096,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			setupTestData(t, dataPath, hashPath, tt.dataSize)

			if err := testCreateAndVerify(t, tt.params, dataPath, hashPath); (err != nil) != tt.wantErr {
				t.Errorf("testCreateAndVerify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestVerityHashCorruption tests data corruption detection
func TestVerityHashCorruption(t *testing.T) {
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.img")
	hashPath := filepath.Join(tmpDir, "hash.img")
	dataSize := uint64(1024 * 1024)
	params := setupVerityTestParams(dataSize)

	setupTestData(t, dataPath, hashPath, dataSize)

	// Create initial hash and save root hash
	vh := NewVerityHash(params, dataPath, hashPath, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("Failed to create initial hash: %v", err)
	}
	rootHash := make([]byte, vh.hashFunc.Size())
	copy(rootHash, vh.rootHash)

	// Corrupt data and verify it fails
	if err := corruptFile(dataPath, 1000); err != nil {
		t.Fatalf("Failed to corrupt data: %v", err)
	}

	vh = NewVerityHash(params, dataPath, hashPath, rootHash)
	if err := vh.Verify(); err == nil {
		t.Error("Verification should fail with corrupted data")
	}
}

// TestAgainstVeritySetup tests compatibility with veritysetup
func TestAgainstVeritySetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping compatibility test")
	}

	tests := []struct {
		name     string
		dataSize uint64
		params   *VerityParams
	}{
		{
			name:     "1MB file with SHA256",
			dataSize: 1024 * 1024,
			params:   setupVerityTestParams(1024 * 1024),
		},
		{
			name:     "1MB file with SHA512",
			dataSize: 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha512",
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataSize:       (1024 * 1024) / 4096,
				HashType:       1,
				Salt:           []byte("test-salt"),
				SaltSize:       uint16(len([]byte("test-salt"))),
				HashAreaOffset: 4096,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			if err := compareVerityImplementations(t, tt.params, dataPath, hashPath); err != nil {
				t.Errorf("Compatibility test failed: %v", err)
			}
		})
	}
}
