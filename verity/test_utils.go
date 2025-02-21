package verity

import (
	"crypto/rand"
	"fmt"
	"os"
)

// createTestDevice creates a test device file with random data
func createTestDevice(size uint64) (string, error) {
	// Create temp file
	f, err := os.CreateTemp("", "verity-test-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}
	defer f.Close()

	// Write random data
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to generate random data: %v", err)
	}

	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to write data: %v", err)
	}

	return f.Name(), nil
}

// createTestParams creates test verity parameters
func createTestParams() *VerityParams {
	return &VerityParams{
		HashName:      "sha256",
		DataBlockSize: 4096,
		HashBlockSize: 4096,
		DataSize:      256, // 1MB of data
		HashType:      1,
		Salt:          []byte("test salt"),
		SaltSize:      9,
	}
}
