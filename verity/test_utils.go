package verity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
)

// setupTestData prepares test data
func setupTestData(t *testing.T, dataPath, hashPath string, dataSize uint64) {
	t.Helper()

	data := make([]byte, dataSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}
	if err := os.WriteFile(dataPath, data, 0644); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	// Use the same block size as in the test parameters
	hashSize := calculateHashDeviceSize(dataSize, 4096, 32)
	hashData := make([]byte, hashSize)
	if err := os.WriteFile(hashPath, hashData, 0644); err != nil {
		t.Fatalf("Failed to create hash file: %v", err)
	}
}

// setupVerityTestParams creates test parameters
func setupVerityTestParams(dataSize uint64) *VerityParams {
	return &VerityParams{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataSize:       dataSize / 4096,
		HashType:       1,
		Salt:           make([]byte, 32), // Use 32-byte empty salt to match veritysetup default
		SaltSize:       32,
		HashAreaOffset: 4096, // Start after first block
	}
}

// calculateHashDeviceSize calculates the hash device size
func calculateHashDeviceSize(dataSize uint64, blockSize uint32, hashSize uint32) uint64 {
	blocks := dataSize / uint64(blockSize)
	if dataSize%uint64(blockSize) != 0 {
		blocks++
	}

	totalBlocks := uint64(0)
	remainingBlocks := blocks
	hashPerBlock := blockSize / hashSize

	for remainingBlocks > 1 {
		remainingBlocks = (remainingBlocks + uint64(hashPerBlock) - 1) / uint64(hashPerBlock)
		totalBlocks += remainingBlocks
	}

	return totalBlocks * uint64(blockSize)
}

// getVeritySetupRootHash gets the root hash from veritysetup
func getVeritySetupRootHash(t *testing.T, dataPath string, hashPath string, params *VerityParams) ([]byte, error) {
	// Construct veritysetup command
	cmd := exec.Command("veritysetup", "format", "--no-superblock",
		dataPath, hashPath+".verity",
		"--hash="+params.HashName,
		"--data-block-size="+strconv.Itoa(int(params.DataBlockSize)),
		"--hash-block-size="+strconv.Itoa(int(params.HashBlockSize)),
		"--salt="+hex.EncodeToString(params.Salt),
	)

	// Execute and parse output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("veritysetup failed: %v\nOutput: %s", err, output)
	}

	// Extract root hash from output
	re := regexp.MustCompile(`Root hash:\s+([0-9a-fA-F]+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return nil, fmt.Errorf("failed to parse root hash from output")
	}

	rootHash, err := hex.DecodeString(matches[1])
	if err != nil {
		return nil, fmt.Errorf("invalid root hash format: %v", err)
	}

	return rootHash, nil
}

// readFileContent reads the entire content of a file
func readFileContent(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return content, nil
}
