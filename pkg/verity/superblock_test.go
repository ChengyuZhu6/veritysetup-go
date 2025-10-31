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
	sb := DefaultVeritySuperblock()
	if string(sb.Signature[:]) != VeritySignature {
		t.Errorf("Expected signature %s, got %s", VeritySignature, string(sb.Signature[:]))
	}
	if sb.Version != 1 {
		t.Errorf("Expected version 1, got %d", sb.Version)
	}
	if sb.HashType != 1 {
		t.Errorf("Expected hash type 1, got %d", sb.HashType)
	}
	sb.DataBlockSize = 4096
	sb.HashBlockSize = 4096
	sb.DataBlocks = 1000
	sb.SaltSize = 16
	copy(sb.Algorithm[:], "sha256")
	for i := 0; i < int(sb.SaltSize); i++ {
		sb.Salt[i] = byte(i)
	}
	data, err := sb.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize superblock: %v", err)
	}
	if len(data) != VeritySuperblockSize {
		t.Errorf("Expected serialized data length %d, got %d", VeritySuperblockSize, len(data))
	}
	sb2, err := DeserializeSuperblock(data)
	if err != nil {
		t.Fatalf("Failed to deserialize superblock: %v", err)
	}
	if string(sb2.Signature[:]) != string(sb.Signature[:]) {
		t.Errorf("Signature mismatch: expected %s, got %s", string(sb.Signature[:]), string(sb2.Signature[:]))
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
	if !bytes.Equal(bytes.TrimRight(sb2.Algorithm[:], "\x00"), bytes.TrimRight(sb.Algorithm[:], "\x00")) {
		t.Errorf("Algorithm mismatch: expected %s, got %s", string(bytes.TrimRight(sb.Algorithm[:], "\x00")), string(bytes.TrimRight(sb2.Algorithm[:], "\x00")))
	}
	for i := 0; i < int(sb.SaltSize); i++ {
		if sb2.Salt[i] != sb.Salt[i] {
			t.Errorf("Salt mismatch at index %d: expected %d, got %d", i, sb.Salt[i], sb2.Salt[i])
		}
	}
}

func TestDeserializeSuperBlockErrors(t *testing.T) {
	_, err := DeserializeSuperblock(make([]byte, VeritySuperblockSize-1))
	if err == nil {
		t.Error("Expected error for data too short, got nil")
	}
	invalidSig := make([]byte, VeritySuperblockSize)
	copy(invalidSig, "invalid!")
	_, err = DeserializeSuperblock(invalidSig)
	if err == nil {
		t.Error("Expected error for invalid signature, got nil")
	}
	validSig := make([]byte, VeritySuperblockSize)
	copy(validSig, VeritySignature)
	validSig[8] = 2
	_, err = DeserializeSuperblock(validSig)
	if err == nil {
		t.Error("Expected error for unsupported version, got nil")
	}
}

func TestSuperBlockRoundTrip(t *testing.T) {
	sb := &VeritySuperblock{}
	copy(sb.Signature[:], VeritySignature)
	sb.Version = 1
	sb.HashType = 1
	sb.DataBlockSize = 4096
	sb.HashBlockSize = 4096
	sb.DataBlocks = 1000
	sb.SaltSize = 32
	for i := 0; i < len(sb.UUID); i++ {
		sb.UUID[i] = byte(i)
	}
	copy(sb.Algorithm[:], "sha256")
	for i := 0; i < int(sb.SaltSize); i++ {
		sb.Salt[i] = byte(i % 256)
	}
	data, err := sb.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize superblock: %v", err)
	}
	sb2, err := DeserializeSuperblock(data)
	if err != nil {
		t.Fatalf("Failed to deserialize superblock: %v", err)
	}
	if !reflect.DeepEqual(sb, sb2) {
		t.Error("Superblocks are not equal after round trip")
		t.Logf("Original: %+v", sb)
		t.Logf("Deserialized: %+v", sb2)
	}
}

func TestSuperBlockAgainstVeritySetup(t *testing.T) {
	_, err := exec.LookPath("veritysetup")
	if err != nil {
		t.Skip("veritysetup not found, skipping compatibility test")
	}
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.img")
	hashPath := filepath.Join(tmpDir, "hash.img")
	dataSize := uint64(1024 * 1024)
	dataBlockSize := uint32(4096)
	hashBlockSize := uint32(4096)
	hashName := "sha256"
	salt := "0123456789abcdef0123456789abcdef"
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}
	p := setupVerityTestParams(dataSize)
	if err := setupTestData(dataPath, hashPath, p, dataSize); err != nil {
		t.Fatalf("setupTestData failed: %v", err)
	}
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
	sb, err := DeserializeSuperblock(sbData)
	if err != nil {
		t.Fatalf("Failed to deserialize superblock: %v", err)
	}
	goSb := DefaultVeritySuperblock()
	goSb.DataBlockSize = dataBlockSize
	goSb.HashBlockSize = hashBlockSize
	goSb.DataBlocks = dataSize / uint64(dataBlockSize)
	copy(goSb.Algorithm[:], hashName)
	goSb.SaltSize = uint16(len(saltBytes))
	copy(goSb.Salt[:], saltBytes)
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
	for i := 0; i < int(sb.SaltSize); i++ {
		if sb.Salt[i] != goSb.Salt[i] {
			t.Errorf("Salt mismatch at index %d: expected %d, got %d", i, goSb.Salt[i], sb.Salt[i])
		}
	}
}

func TestSuperblockErrorHandling(t *testing.T) {
	t.Run("DeserializeEmptyData", func(t *testing.T) {
		_, err := DeserializeSuperblock([]byte{})
		if err == nil {
			t.Error("Expected error for empty data, got nil")
		}
	})

	t.Run("DeserializePartialData", func(t *testing.T) {
		partialData := make([]byte, VeritySuperblockSize/2)
		_, err := DeserializeSuperblock(partialData)
		if err == nil {
			t.Error("Expected error for partial data, got nil")
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		data := make([]byte, VeritySuperblockSize)
		copy(data, "INVALID!")
		_, err := DeserializeSuperblock(data)
		if err == nil {
			t.Error("Expected error for invalid signature, got nil")
		}
	})

	t.Run("UnsupportedVersion", func(t *testing.T) {
		data := make([]byte, VeritySuperblockSize)
		copy(data, VeritySignature)
		data[8] = 99
		_, err := DeserializeSuperblock(data)
		if err == nil {
			t.Error("Expected error for unsupported version, got nil")
		}
	})

	t.Run("InvalidHashType", func(t *testing.T) {
		sb := DefaultVeritySuperblock()
		sb.HashType = 99
		data, err := sb.Serialize()
		if err != nil {
			t.Errorf("Serialize failed: %v", err)
		}
		sb2, err := DeserializeSuperblock(data)
		if err != nil {
			t.Errorf("Deserialize failed: %v", err)
		}
		if sb2.HashType != 99 {
			t.Errorf("Expected hash type 99, got %d", sb2.HashType)
		}
	})
}

func TestSuperblockBoundaryConditions(t *testing.T) {
	t.Run("MinimalSuperblock", func(t *testing.T) {
		sb := DefaultVeritySuperblock()
		sb.DataBlockSize = 512
		sb.HashBlockSize = 512
		sb.DataBlocks = 1
		sb.SaltSize = 0
		copy(sb.Algorithm[:], "sha256")

		data, err := sb.Serialize()
		if err != nil {
			t.Fatalf("Failed to serialize minimal superblock: %v", err)
		}

		sb2, err := DeserializeSuperblock(data)
		if err != nil {
			t.Fatalf("Failed to deserialize minimal superblock: %v", err)
		}

		if !reflect.DeepEqual(&sb, sb2) {
			t.Error("Minimal superblock round trip failed")
			t.Logf("Original: %+v", sb)
			t.Logf("Deserialized: %+v", *sb2)
		}
	})

	t.Run("MaxSaltSize", func(t *testing.T) {
		sb := DefaultVeritySuperblock()
		sb.SaltSize = 256
		for i := 0; i < 256; i++ {
			sb.Salt[i] = byte(i)
		}

		data, err := sb.Serialize()
		if err != nil {
			t.Fatalf("Failed to serialize superblock with max salt: %v", err)
		}

		sb2, err := DeserializeSuperblock(data)
		if err != nil {
			t.Fatalf("Failed to deserialize superblock with max salt: %v", err)
		}

		if sb2.SaltSize != 256 {
			t.Errorf("Expected salt size 256, got %d", sb2.SaltSize)
		}

		for i := 0; i < 256; i++ {
			if sb2.Salt[i] != byte(i) {
				t.Errorf("Salt mismatch at index %d", i)
			}
		}
	})

	t.Run("LargeDataBlocks", func(t *testing.T) {
		sb := DefaultVeritySuperblock()
		sb.DataBlocks = 1<<32 - 1

		data, err := sb.Serialize()
		if err != nil {
			t.Fatalf("Failed to serialize superblock with large data blocks: %v", err)
		}

		sb2, err := DeserializeSuperblock(data)
		if err != nil {
			t.Fatalf("Failed to deserialize superblock with large data blocks: %v", err)
		}

		if sb2.DataBlocks != sb.DataBlocks {
			t.Errorf("DataBlocks mismatch: expected %d, got %d", sb.DataBlocks, sb2.DataBlocks)
		}
	})

	t.Run("DifferentHashAlgorithms", func(t *testing.T) {
		algorithms := []string{"sha1", "sha256", "sha512"}
		for _, algo := range algorithms {
			sb := DefaultVeritySuperblock()
			for i := range sb.Algorithm {
				sb.Algorithm[i] = 0
			}
			copy(sb.Algorithm[:], algo)

			data, err := sb.Serialize()
			if err != nil {
				t.Fatalf("Failed to serialize superblock with %s: %v", algo, err)
			}

			sb2, err := DeserializeSuperblock(data)
			if err != nil {
				t.Fatalf("Failed to deserialize superblock with %s: %v", algo, err)
			}

			algoStr := string(bytes.TrimRight(sb2.Algorithm[:], "\x00"))
			if algoStr != algo {
				t.Errorf("Algorithm mismatch: expected %s, got %s", algo, algoStr)
			}
		}
	})
}

func TestNewSuperblock(t *testing.T) {
	sb := NewSuperblock()
	if sb == nil {
		t.Fatal("NewSuperblock() returned nil")
	}

	if string(sb.Signature[:]) != VeritySignature {
		t.Errorf("Expected signature %s, got %s", VeritySignature, string(sb.Signature[:]))
	}

	if sb.Version != 1 {
		t.Errorf("Expected version 1, got %d", sb.Version)
	}

	if sb.HashType != 1 {
		t.Errorf("Expected hash type 1, got %d", sb.HashType)
	}
}

func TestAdoptParamsFromSuperblock(t *testing.T) {
	sb := DefaultVeritySuperblock()
	sb.DataBlockSize = 8192
	sb.HashBlockSize = 4096
	sb.DataBlocks = 1000
	sb.SaltSize = 16
	copy(sb.Algorithm[:], "sha512")
	for i := 0; i < 16; i++ {
		sb.Salt[i] = byte(i)
	}

	params := &VerityParams{}
	if err := AdoptParamsFromSuperblock(params, &sb); err != nil {
		t.Fatalf("AdoptParamsFromSuperblock failed: %v", err)
	}

	if params.HashName != "sha512" {
		t.Errorf("Expected hash name 'sha512', got '%s'", params.HashName)
	}

	if params.DataBlockSize != 8192 {
		t.Errorf("Expected data block size 8192, got %d", params.DataBlockSize)
	}

	if params.HashBlockSize != 4096 {
		t.Errorf("Expected hash block size 4096, got %d", params.HashBlockSize)
	}

	if params.DataBlocks != 1000 {
		t.Errorf("Expected data blocks 1000, got %d", params.DataBlocks)
	}

	if params.SaltSize != 16 {
		t.Errorf("Expected salt size 16, got %d", params.SaltSize)
	}

	if len(params.Salt) != 16 {
		t.Errorf("Expected salt length 16, got %d", len(params.Salt))
	}

	for i := 0; i < 16; i++ {
		if params.Salt[i] != byte(i) {
			t.Errorf("Salt mismatch at index %d: expected %d, got %d", i, i, params.Salt[i])
		}
	}
}
