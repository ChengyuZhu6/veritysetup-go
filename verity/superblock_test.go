package verity

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSuperBlockSerialization(t *testing.T) {
	// Create a new superblock with default values
	sb := NewSuperBlock()

	// Verify default values
	if string(sb.Signature[:]) != VeritySignature {
		t.Errorf("Expected signature %s, got %s", VeritySignature, string(sb.Signature[:]))
	}
	if sb.Version != 1 {
		t.Errorf("Expected version 1, got %d", sb.Version)
	}
	if sb.HashType != 1 {
		t.Errorf("Expected hash type 1, got %d", sb.HashType)
	}

	// Set some custom values
	sb.DataBlockSize = 4096
	sb.HashBlockSize = 4096
	sb.DataBlocks = 1000
	sb.SaltSize = 16
	copy(sb.Algorithm[:], "sha256")

	// Fill salt with some test data
	for i := 0; i < int(sb.SaltSize); i++ {
		sb.Salt[i] = byte(i)
	}

	// Serialize the superblock
	data, err := sb.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize superblock: %v", err)
	}

	// Verify the serialized data length
	if len(data) != VeritySuperblockSize {
		t.Errorf("Expected serialized data length %d, got %d", VeritySuperblockSize, len(data))
	}

	// Deserialize the data back to a superblock
	sb2, err := DeserializeSuperBlock(data)
	if err != nil {
		t.Fatalf("Failed to deserialize superblock: %v", err)
	}

	// Verify the deserialized values match the original
	if string(sb2.Signature[:]) != string(sb.Signature[:]) {
		t.Errorf("Signature mismatch: expected %s, got %s",
			string(sb.Signature[:]), string(sb2.Signature[:]))
	}
	if sb2.Version != sb.Version {
		t.Errorf("Version mismatch: expected %d, got %d", sb.Version, sb2.Version)
	}
	if sb2.HashType != sb.HashType {
		t.Errorf("HashType mismatch: expected %d, got %d", sb.HashType, sb2.HashType)
	}
	if sb2.DataBlockSize != sb.DataBlockSize {
		t.Errorf("DataBlockSize mismatch: expected %d, got %d", sb.DataBlockSize, sb2.DataBlockSize)
	}
	if sb2.HashBlockSize != sb.HashBlockSize {
		t.Errorf("HashBlockSize mismatch: expected %d, got %d", sb.HashBlockSize, sb2.HashBlockSize)
	}
	if sb2.DataBlocks != sb.DataBlocks {
		t.Errorf("DataBlocks mismatch: expected %d, got %d", sb.DataBlocks, sb2.DataBlocks)
	}
	if sb2.SaltSize != sb.SaltSize {
		t.Errorf("SaltSize mismatch: expected %d, got %d", sb.SaltSize, sb2.SaltSize)
	}

	// Check algorithm
	if !bytes.Equal(bytes.TrimRight(sb2.Algorithm[:], "\x00"), bytes.TrimRight(sb.Algorithm[:], "\x00")) {
		t.Errorf("Algorithm mismatch: expected %s, got %s",
			string(bytes.TrimRight(sb.Algorithm[:], "\x00")),
			string(bytes.TrimRight(sb2.Algorithm[:], "\x00")))
	}

	// Check salt
	for i := 0; i < int(sb.SaltSize); i++ {
		if sb2.Salt[i] != sb.Salt[i] {
			t.Errorf("Salt mismatch at index %d: expected %d, got %d", i, sb.Salt[i], sb2.Salt[i])
		}
	}
}

func TestDeserializeSuperBlockErrors(t *testing.T) {
	// Test with data too short
	_, err := DeserializeSuperBlock(make([]byte, VeritySuperblockSize-1))
	if err == nil {
		t.Error("Expected error for data too short, got nil")
	}

	// Test with invalid signature
	invalidSig := make([]byte, VeritySuperblockSize)
	copy(invalidSig, "invalid!")
	_, err = DeserializeSuperBlock(invalidSig)
	if err == nil {
		t.Error("Expected error for invalid signature, got nil")
	}

	// Test with invalid version
	validSig := make([]byte, VeritySuperblockSize)
	copy(validSig, VeritySignature)
	validSig[8] = 2 // Set version to 2 (unsupported)
	_, err = DeserializeSuperBlock(validSig)
	if err == nil {
		t.Error("Expected error for unsupported version, got nil")
	}
}

func TestSuperBlockRoundTrip(t *testing.T) {
	// Create a fully populated superblock
	sb := &VeritySuperblock{}
	copy(sb.Signature[:], VeritySignature)
	sb.Version = 1
	sb.HashType = 1
	sb.DataBlockSize = 4096
	sb.HashBlockSize = 4096
	sb.DataBlocks = 1000
	sb.SaltSize = 32

	// Set UUID
	for i := 0; i < len(sb.UUID); i++ {
		sb.UUID[i] = byte(i)
	}

	// Set algorithm
	copy(sb.Algorithm[:], "sha256")

	// Set salt
	for i := 0; i < int(sb.SaltSize); i++ {
		sb.Salt[i] = byte(i % 256)
	}

	// Serialize
	data, err := sb.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize superblock: %v", err)
	}

	// Deserialize
	sb2, err := DeserializeSuperBlock(data)
	if err != nil {
		t.Fatalf("Failed to deserialize superblock: %v", err)
	}

	// Compare the two superblocks
	if !reflect.DeepEqual(sb, sb2) {
		t.Error("Superblocks are not equal after round trip")

		// Print detailed differences for debugging
		t.Logf("Original: %+v", sb)
		t.Logf("Deserialized: %+v", sb2)
	}
}

func TestSuperBlockAgainstVeritySetup(t *testing.T) {
	// Skip if veritysetup is not installed
	_, err := exec.LookPath("veritysetup")
	if err != nil {
		t.Skip("veritysetup not found, skipping compatibility test")
	}

	// Create temporary directory for test files
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.img")
	hashPath := filepath.Join(tmpDir, "hash.img")

	// Test parameters
	dataSize := uint64(1024 * 1024) // 1MB
	dataBlockSize := uint32(4096)
	hashBlockSize := uint32(4096)
	hashName := "sha256"
	salt := "0123456789abcdef0123456789abcdef" // 32-byte hex salt
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}

	// Setup test data using existing utility function
	setupTestData(t, dataPath, hashPath, dataSize)

	// Run veritysetup format
	cmd := exec.Command(
		"veritysetup", "format",
		"--data-block-size", fmt.Sprintf("%d", dataBlockSize),
		"--hash-block-size", fmt.Sprintf("%d", hashBlockSize),
		"--hash", hashName,
		"--salt", salt,
		dataPath, hashPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup failed: %v\nOutput: %s", err, output)
	}

	// Read the superblock from the hash file
	hashFile, err := os.Open(hashPath)
	if err != nil {
		t.Fatalf("Failed to open hash file: %v", err)
	}
	defer hashFile.Close()

	sbData := make([]byte, VeritySuperblockSize)
	_, err = hashFile.Read(sbData)
	if err != nil {
		t.Fatalf("Failed to read superblock: %v", err)
	}

	// Deserialize the superblock
	sb, err := DeserializeSuperBlock(sbData)
	if err != nil {
		t.Fatalf("Failed to deserialize superblock: %v", err)
	}

	// Create a superblock with our Go implementation
	goSb := NewSuperBlock()
	goSb.DataBlockSize = dataBlockSize
	goSb.HashBlockSize = hashBlockSize
	goSb.DataBlocks = dataSize / uint64(dataBlockSize)
	copy(goSb.Algorithm[:], hashName)
	goSb.SaltSize = uint16(len(saltBytes))
	copy(goSb.Salt[:], saltBytes)

	// Use table-driven tests for field comparisons
	tests := []struct {
		name     string
		expected interface{}
		actual   interface{}
	}{
		{"Signature", string(goSb.Signature[:]), string(sb.Signature[:])},
		{"Version", goSb.Version, sb.Version},
		{"HashType", goSb.HashType, sb.HashType},
		{"DataBlockSize", goSb.DataBlockSize, sb.DataBlockSize},
		{"HashBlockSize", goSb.HashBlockSize, sb.HashBlockSize},
		{"DataBlocks", goSb.DataBlocks, sb.DataBlocks},
		{"SaltSize", goSb.SaltSize, sb.SaltSize},
		{"Algorithm", string(bytes.TrimRight(goSb.Algorithm[:], "\x00")), string(bytes.TrimRight(sb.Algorithm[:], "\x00"))},
	}

	for _, tc := range tests {
		if !reflect.DeepEqual(tc.expected, tc.actual) {
			t.Errorf("%s mismatch: expected %v, got %v", tc.name, tc.expected, tc.actual)
		}
	}

	// Check salt (needs special handling due to array comparison)
	for i := 0; i < int(sb.SaltSize); i++ {
		if sb.Salt[i] != goSb.Salt[i] {
			t.Errorf("Salt mismatch at index %d: expected %d, got %d",
				i, goSb.Salt[i], sb.Salt[i])
		}
	}
}
