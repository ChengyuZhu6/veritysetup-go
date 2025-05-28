package verity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

// setupTestData creates test data and hash files
func setupTestData(t *testing.T, dataPath, hashPath string, dataSize uint64) {
	t.Helper()

	// Generate random test data
	if err := generateRandomFile(dataPath, dataSize); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Create empty hash file
	hashSize := calculateHashDeviceSize(dataSize, 4096, 32)
	if err := createEmptyFile(hashPath, hashSize); err != nil {
		t.Fatalf("Failed to create hash file: %v", err)
	}
}

// generateRandomFile creates a file with random content
func generateRandomFile(path string, size uint64) error {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return fmt.Errorf("failed to generate random data: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// createEmptyFile creates an empty file of specified size
func createEmptyFile(path string, size uint64) error {
	data := make([]byte, size)
	return os.WriteFile(path, data, 0644)
}

// setupVerityTestParams creates default test parameters
func setupVerityTestParams(dataSize uint64) *VerityParams {
	params := DefaultVerityParams()
	params.DataBlocks = dataSize / 4096
	params.Salt = make([]byte, 32)
	params.SaltSize = 32
	params.HashAreaOffset = 8192
	return &params
}

// calculateHashDeviceSize calculates the required hash device size
func calculateHashDeviceSize(dataSize uint64, blockSize uint32, hashSize uint32) uint64 {
	blocks := (dataSize + uint64(blockSize) - 1) / uint64(blockSize)
	hashBlocks := (blocks + uint64(blockSize/hashSize) - 1) / uint64(blockSize/hashSize)
	return hashBlocks * uint64(blockSize)
}

// getVeritySetupRootHash gets the root hash from veritysetup
func getVeritySetupRootHash(dataPath string, hashPath string, params *VerityParams) ([]byte, error) {
	// Construct veritysetup command
	cmd := exec.Command("veritysetup", "format",
		dataPath, hashPath+".verity",
		"--hash", params.HashName,
		"--data-block-size", strconv.FormatUint(uint64(params.DataBlockSize), 10),
		"--hash-block-size", strconv.FormatUint(uint64(params.HashBlockSize), 10),
		"--salt", hex.EncodeToString(params.Salt))

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("veritysetup failed: %w", err)
	}

	// Parse root hash from output
	for _, line := range bytes.Split(output, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("Root hash:")) {
			hexHash := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("Root hash:")))
			rootHash := make([]byte, hex.DecodedLen(len(hexHash)))
			if _, err := hex.Decode(rootHash, hexHash); err != nil {
				return nil, fmt.Errorf("failed to decode root hash: %w", err)
			}
			return rootHash, nil
		}
	}

	return nil, fmt.Errorf("root hash not found in veritysetup output")
}

// readFileContent reads entire file content
func readFileContent(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return content, nil
}

// compareVerityImplementations compares our implementation with veritysetup
func compareVerityImplementations(t *testing.T, params *VerityParams, dataPath, hashPath string) error {
	// Prepare test data
	setupTestData(t, dataPath, hashPath, params.DataBlocks*uint64(params.DataBlockSize))

	// Use our implementation to generate hash
	ourVh := NewVerityHash(params, dataPath, hashPath, nil)
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
	veritysetupRootHash, err := getVeritySetupRootHash(dataPath, hashPath, params)
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

// corruptFile corrupts a file at specific offset
func corruptFile(path string, offset int64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteAt([]byte{0xFF}, offset)
	return err
}
