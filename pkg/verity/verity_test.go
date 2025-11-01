// Package verity provides tests for dm-verity functionality
package verity

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func extractUUID(t *testing.T, output string) string {
	t.Helper()
	re := regexp.MustCompile(`(?i)UUID:\s*([0-9a-f-]+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) < 2 {
		t.Fatalf("failed to extract UUID from output: %s", output)
	}
	return matches[1]
}

func TestGenerateUUID(t *testing.T) {
	uuidStr, err := GenerateUUID()
	if err != nil {
		t.Fatalf("GenerateUUID failed: %v", err)
	}

	// Verify it's a valid UUID
	_, err = uuid.Parse(uuidStr)
	if err != nil {
		t.Fatalf("Generated UUID is invalid: %v", err)
	}

	// Generate another and ensure they're different
	uuidStr2, err := GenerateUUID()
	if err != nil {
		t.Fatalf("GenerateUUID failed on second call: %v", err)
	}

	if uuidStr == uuidStr2 {
		t.Error("Two generated UUIDs should be different")
	}
}

func TestGetHashSize(t *testing.T) {
	tests := []struct {
		name     string
		hashName string
		expected int
	}{
		{"sha1", "sha1", 20},
		{"sha256", "sha256", 32},
		{"sha512", "sha512", 64},
		{"SHA256 uppercase", "SHA256", 32},
		{"sha256 with spaces", "  sha256  ", 32},
		{"unsupported", "md5", -1},
		{"empty", "", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getHashSize(tt.hashName)
			if result != tt.expected {
				t.Errorf("getHashSize(%q) = %d, want %d", tt.hashName, result, tt.expected)
			}
		})
	}
}

func TestUint64MultOverflow(t *testing.T) {
	tests := []struct {
		name     string
		a        uint64
		b        uint64
		overflow bool
	}{
		{"no overflow small", 100, 200, false},
		{"no overflow zero", 0, 1000, false},
		{"no overflow one", 1, 1000, false},
		{"overflow max", ^uint64(0), 2, true},
		{"overflow large", ^uint64(0) / 2, 3, true},
		{"no overflow max by 1", ^uint64(0), 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uint64MultOverflow(tt.a, tt.b)
			if result != tt.overflow {
				t.Errorf("uint64MultOverflow(%d, %d) = %v, want %v", tt.a, tt.b, result, tt.overflow)
			}
		})
	}
}

func TestHashOffsetBlock(t *testing.T) {
	tests := []struct {
		name     string
		params   *VerityParams
		expected uint64
	}{
		{
			name: "no superblock",
			params: &VerityParams{
				HashAreaOffset: 8192,
				HashBlockSize:  4096,
				NoSuperblock:   true,
			},
			expected: 2, // 8192 / 4096
		},
		{
			name: "with superblock",
			params: &VerityParams{
				HashAreaOffset: 0,
				HashBlockSize:  4096,
				NoSuperblock:   false,
			},
			expected: 1, // (0 + 512 + 4096 - 1) / 4096 = 4607 / 4096 = 1
		},
		{
			name: "with superblock and offset",
			params: &VerityParams{
				HashAreaOffset: 4096,
				HashBlockSize:  4096,
				NoSuperblock:   false,
			},
			expected: 2, // (4096 + 512 + 4096 - 1) / 4096 = 8703 / 4096 = 2
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashOffsetBlock(tt.params)
			if result != tt.expected {
				t.Errorf("HashOffsetBlock() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestHashOffsetBlockCalculation(t *testing.T) {
	tests := []struct {
		name           string
		hashAreaOffset uint64
		hashBlockSize  uint32
		noSuperblock   bool
		expected       uint64
	}{
		{
			name:           "no superblock, aligned",
			hashAreaOffset: 8192,
			hashBlockSize:  4096,
			noSuperblock:   true,
			expected:       2, // 8192 / 4096
		},
		{
			name:           "with superblock, offset 0",
			hashAreaOffset: 0,
			hashBlockSize:  4096,
			noSuperblock:   false,
			expected:       1, // (0 + 512 + 4095) / 4096
		},
		{
			name:           "with superblock, offset 4096",
			hashAreaOffset: 4096,
			hashBlockSize:  4096,
			noSuperblock:   false,
			expected:       2, // (4096 + 512 + 4095) / 4096
		},
		{
			name:           "no superblock, large offset",
			hashAreaOffset: 1048576, // 1MB
			hashBlockSize:  4096,
			noSuperblock:   true,
			expected:       256, // 1048576 / 4096
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &VerityParams{
				HashAreaOffset: tt.hashAreaOffset,
				HashBlockSize:  tt.hashBlockSize,
				NoSuperblock:   tt.noSuperblock,
			}

			result := HashOffsetBlock(params)
			if result != tt.expected {
				t.Errorf("HashOffsetBlock() = %d, want %d", result, tt.expected)
			} else {
				t.Logf("✓ Correct offset: %d blocks", result)
			}
		})
	}
}

func TestVerityHashBlocksCalculation(t *testing.T) {
	tests := []struct {
		name          string
		dataBlocks    uint64
		dataBlockSize uint32
		hashBlockSize uint32
		hashAlgo      string
	}{
		{
			name:          "small dataset sha256",
			dataBlocks:    16,
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			hashAlgo:      "sha256",
		},
		{
			name:          "medium dataset sha256",
			dataBlocks:    1024,
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			hashAlgo:      "sha256",
		},
		{
			name:          "large dataset sha512",
			dataBlocks:    4096,
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			hashAlgo:      "sha512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &VerityParams{
				HashName:       tt.hashAlgo,
				DataBlockSize:  tt.dataBlockSize,
				HashBlockSize:  tt.hashBlockSize,
				DataBlocks:     tt.dataBlocks,
				HashType:       1,
				HashAreaOffset: 0,
			}

			digestSize := getHashSize(tt.hashAlgo)
			if digestSize <= 0 {
				t.Fatalf("Invalid hash algorithm: %s", tt.hashAlgo)
			}

			hashBlocks, err := VerityHashBlocks(params, digestSize)
			if err != nil {
				t.Fatalf("VerityHashBlocks failed: %v", err)
			}

			t.Logf("Data blocks: %d, Hash blocks needed: %d", tt.dataBlocks, hashBlocks)

			if hashBlocks > tt.dataBlocks {
				t.Errorf("Hash blocks (%d) should not exceed data blocks (%d)", hashBlocks, tt.dataBlocks)
			}

			if hashBlocks == 0 && tt.dataBlocks > 0 {
				t.Error("Hash blocks should be > 0 for non-empty dataset")
			}
		})
	}
}

func TestDumpInfo(t *testing.T) {
	params := &VerityParams{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataBlocks:     1024,
		HashType:       1,
		Salt:           []byte{0x01, 0x02, 0x03, 0x04},
		SaltSize:       4,
		HashAreaOffset: 0,
	}

	rootHash := []byte{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}

	info, err := DumpInfo(params, rootHash)
	if err != nil {
		t.Fatalf("DumpInfo failed: %v", err)
	}

	// Check that info contains expected strings
	expectedStrings := []string{
		"VERITY header information",
		"Hash type:",
		"Data blocks:",
		"Data block size:",
		"Hash blocks:",
		"Hash block size:",
		"Hash algorithm:",
		"Salt:",
		"Root hash:",
	}

	for _, expected := range expectedStrings {
		if !bytes.Contains([]byte(info), []byte(expected)) {
			t.Errorf("DumpInfo output missing expected string: %q", expected)
		}
	}
}

func TestDumpInfoNilParams(t *testing.T) {
	_, err := DumpInfo(nil, nil)
	if err == nil {
		t.Error("DumpInfo with nil params should return error")
	}
}

func TestDumpInfoComparison(t *testing.T) {
	params := &VerityParams{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataBlocks:     1024,
		HashType:       1,
		Salt:           []byte{0x01, 0x02, 0x03, 0x04},
		SaltSize:       4,
		HashAreaOffset: 0,
	}

	rootHash := make([]byte, 32)
	for i := range rootHash {
		rootHash[i] = byte(i)
	}

	info, err := DumpInfo(params, rootHash)
	if err != nil {
		t.Fatalf("DumpInfo failed: %v", err)
	}

	t.Logf("DumpInfo output:\n%s", info)

	expectedFields := map[string]bool{
		"Hash type:":       false,
		"Data blocks:":     false,
		"Data block size:": false,
		"Hash blocks:":     false,
		"Hash block size:": false,
		"Hash algorithm:":  false,
		"Salt:":            false,
		"Root hash:":       false,
	}

	for field := range expectedFields {
		if strings.Contains(info, field) {
			expectedFields[field] = true
		}
	}

	for field, found := range expectedFields {
		if !found {
			t.Errorf("DumpInfo output missing field: %s", field)
		}
	}

	if !strings.Contains(info, "sha256") {
		t.Error("DumpInfo should contain hash algorithm name")
	}
	if !strings.Contains(info, "1024") {
		t.Error("DumpInfo should contain data blocks count")
	}
	if !strings.Contains(info, "4096") {
		t.Error("DumpInfo should contain block sizes")
	}
}

func TestVerifyParamsNilParams(t *testing.T) {
	err := VerifyParams(nil, "", "", nil, false)
	if err == nil {
		t.Error("VerifyParams with nil params should return error")
	}
}

func TestVerifyParamsNilRootHash(t *testing.T) {
	params := DefaultVerityParams()
	err := VerifyParams(&params, "", "", nil, false)
	if err == nil {
		t.Error("VerifyParams with nil root hash should return error")
	}
}

func TestVerifyParamsNoCheck(t *testing.T) {
	params := DefaultVerityParams()
	rootHash := make([]byte, 32)

	// Should succeed without actual verification when checkHash is false
	err := VerifyParams(&params, "", "", rootHash, false)
	if err != nil {
		t.Errorf("VerifyParams with checkHash=false should not fail: %v", err)
	}
}

func TestWriteSuperblockNilParams(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "verity-test-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	err = WriteSuperblock(tmpFile, 0, "550e8400-e29b-41d4-a716-446655440000", nil)
	if err == nil {
		t.Error("WriteSuperblock with nil params should return error")
	}
}

func TestWriteSuperblockNoSuperblock(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "verity-test-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	params := DefaultVerityParams()
	params.NoSuperblock = true

	err = WriteSuperblock(tmpFile, 0, "550e8400-e29b-41d4-a716-446655440000", &params)
	if err == nil {
		t.Error("WriteSuperblock with NoSuperblock=true should return error")
	}
}

func TestWriteSuperblockInvalidUUID(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "verity-test-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	params := DefaultVerityParams()
	params.DataBlocks = 100

	err = WriteSuperblock(tmpFile, 0, "invalid-uuid", &params)
	if err == nil {
		t.Error("WriteSuperblock with invalid UUID should return error")
	}
}

func TestReadVeritySuperblockNilParams(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "verity-test-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	_, err = ReadVeritySuperblock(tmpFile, 0, nil)
	if err == nil {
		t.Error("ReadVeritySuperblock with nil params should return error")
	}
}

func TestReadVeritySuperblockNoSuperblock(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "verity-test-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	params := DefaultVerityParams()
	params.NoSuperblock = true

	_, err = ReadVeritySuperblock(tmpFile, 0, &params)
	if err == nil {
		t.Error("ReadVeritySuperblock with NoSuperblock=true should return error")
	}
}

func TestReadVeritySuperblockUnalignedOffset(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "verity-test-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	params := DefaultVerityParams()

	_, err = ReadVeritySuperblock(tmpFile, 100, &params) // Not 512-byte aligned
	if err == nil {
		t.Error("ReadVeritySuperblock with unaligned offset should return error")
	}
}

func TestSuperblockRoundTrip(t *testing.T) {
	tests := []struct {
		name          string
		dataBlockSize uint32
		hashBlockSize uint32
		numBlocks     uint64
		hashAlgo      string
	}{
		{
			name:          "superblock sha256",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashAlgo:      "sha256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, tt.dataBlockSize, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*4))
			defer os.Remove(hashPath)

			uuidStr, err := GenerateUUID()
			if err != nil {
				t.Fatalf("GenerateUUID failed: %v", err)
			}

			salt := []byte("superblock-test")

			params := &VerityParams{
				HashName:       tt.hashAlgo,
				DataBlockSize:  tt.dataBlockSize,
				HashBlockSize:  tt.hashBlockSize,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           salt,
				SaltSize:       uint16(len(salt)),
				HashAreaOffset: 0, // Superblock at offset 0
				NoSuperblock:   false,
			}

			parsedUUID, _ := uuid.Parse(uuidStr)
			copy(params.UUID[:], parsedUUID[:])

			hashFile, err := os.OpenFile(hashPath, os.O_RDWR, 0)
			if err != nil {
				t.Fatalf("Failed to open hash file: %v", err)
			}

			err = WriteSuperblock(hashFile, 0, uuidStr, params)
			hashFile.Close()
			if err != nil {
				t.Fatalf("WriteSuperblock failed: %v", err)
			}

			t.Logf("Wrote superblock with UUID: %s", uuidStr)

			hashFile2, err := os.Open(hashPath)
			if err != nil {
				t.Fatalf("Failed to open hash file for reading: %v", err)
			}
			defer hashFile2.Close()

			readParams := &VerityParams{}
			readUUID, err := ReadVeritySuperblock(hashFile2, 0, readParams)
			if err != nil {
				t.Fatalf("ReadVeritySuperblock failed: %v", err)
			}

			if strings.ToLower(readUUID) != strings.ToLower(uuidStr) {
				t.Errorf("UUID mismatch:\nWritten: %s\nRead:    %s", uuidStr, readUUID)
			} else {
				t.Logf("✓ UUID match: %s", readUUID)
			}

			if readParams.HashName != params.HashName {
				t.Errorf("HashName mismatch: %s != %s", readParams.HashName, params.HashName)
			}
			if readParams.DataBlockSize != params.DataBlockSize {
				t.Errorf("DataBlockSize mismatch: %d != %d", readParams.DataBlockSize, params.DataBlockSize)
			}
			if readParams.HashBlockSize != params.HashBlockSize {
				t.Errorf("HashBlockSize mismatch: %d != %d", readParams.HashBlockSize, params.HashBlockSize)
			}
			if readParams.DataBlocks != params.DataBlocks {
				t.Errorf("DataBlocks mismatch: %d != %d", readParams.DataBlocks, params.DataBlocks)
			}
			if !bytes.Equal(readParams.Salt, params.Salt) {
				t.Errorf("Salt mismatch")
			}

			t.Logf("✓ All superblock parameters match")
		})
	}
}

func TestHighLevelCreateWithVeritysetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping integration test")
	}

	tests := []struct {
		name          string
		dataBlockSize uint32
		hashBlockSize uint32
		numBlocks     uint64
		hashType      uint32
		hashAlgo      string
		useSalt       bool
		noSuperblock  bool
	}{
		// No superblock tests
		{
			name:          "basic sha256 no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       false,
			noSuperblock:  true,
		},
		{
			name:          "sha256 with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     32,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       true,
			noSuperblock:  true,
		},
		{
			name:          "sha512 no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha512",
			useSalt:       false,
			noSuperblock:  true,
		},
		{
			name:          "sha1 with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     8,
			hashType:      1,
			hashAlgo:      "sha1",
			useSalt:       true,
			noSuperblock:  true,
		},
		// With superblock tests
		{
			name:          "superblock sha256 no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       false,
			noSuperblock:  false,
		},
		{
			name:          "superblock sha256 with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     32,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       true,
			noSuperblock:  false,
		},
		{
			name:          "superblock sha512 no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha512",
			useSalt:       false,
			noSuperblock:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, tt.dataBlockSize, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPathGo := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathGo)

			hashPathC := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathC)

			var salt []byte
			saltArgs := []string{"--salt", "-"}
			veritysetupArgs := []string{}
			if tt.useSalt {
				salt = []byte("integration-test-salt")
				saltHex := hex.EncodeToString(salt)
				saltArgs = []string{"--salt", saltHex}
			}
			if tt.noSuperblock {
				veritysetupArgs = []string{"--no-superblock"}
			}

			var rootHashGo []byte
			if tt.noSuperblock {
				// No superblock mode
				params := &VerityParams{
					HashName:       tt.hashAlgo,
					DataBlockSize:  tt.dataBlockSize,
					HashBlockSize:  tt.hashBlockSize,
					DataBlocks:     tt.numBlocks,
					HashType:       tt.hashType,
					Salt:           salt,
					SaltSize:       uint16(len(salt)),
					HashAreaOffset: 0,
					NoSuperblock:   true,
				}

				var err error
				rootHashGo, err = HighLevelCreate(params, dataPath, hashPathGo)
				if err != nil {
					t.Fatalf("HighLevelCreate (no superblock) failed: %v", err)
				}
			} else {
				// With superblock mode
				uuidStr, err := GenerateUUID()
				if err != nil {
					t.Fatalf("GenerateUUID failed: %v", err)
				}

				params := &VerityParams{
					HashName:       tt.hashAlgo,
					DataBlockSize:  tt.dataBlockSize,
					HashBlockSize:  tt.hashBlockSize,
					DataBlocks:     tt.numBlocks,
					HashType:       tt.hashType,
					Salt:           salt,
					SaltSize:       uint16(len(salt)),
					HashAreaOffset: uint64(tt.hashBlockSize),
					NoSuperblock:   false,
				}

				parsedUUID, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID[:])

				// Write superblock
				hashFile, err := os.OpenFile(hashPathGo, os.O_RDWR, 0)
				if err != nil {
					t.Fatalf("Failed to open hash file: %v", err)
				}
				err = WriteSuperblock(hashFile, 0, uuidStr, params)
				hashFile.Close()
				if err != nil {
					t.Fatalf("WriteSuperblock failed: %v", err)
				}

				// Create hash tree
				creator, err := NewCreator(params, dataPath, hashPathGo)
				if err != nil {
					t.Fatalf("NewCreator failed: %v", err)
				}
				rootHashGo, err = creator.Create()
				if err != nil {
					t.Fatalf("Creator.Create failed: %v", err)
				}
			}

			args := []string{
				"format",
				dataPath,
				hashPathC,
				"--hash", tt.hashAlgo,
				"--data-block-size", "4096",
				"--hash-block-size", "4096",
			}
			args = append(args, saltArgs...)
			args = append(args, veritysetupArgs...)

			cmd := exec.Command("veritysetup", args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("veritysetup format failed: %v\nOutput: %s", err, string(output))
			}

			rootHashC := extractRootHash(t, string(output))
			rootHashCBytes, err := hex.DecodeString(rootHashC)
			if err != nil {
				t.Fatalf("failed to decode veritysetup root hash: %v", err)
			}

			if !bytes.Equal(rootHashGo, rootHashCBytes) {
				t.Errorf("Root hash mismatch:\nGo:          %x\nveritysetup: %x",
					rootHashGo, rootHashCBytes)
			} else {
				t.Logf("✓ Root hash match: %x", rootHashGo)
			}
		})
	}
}

func TestHighLevelVerifyWithVeritysetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping integration test")
	}

	tests := []struct {
		name          string
		dataBlockSize uint32
		hashBlockSize uint32
		numBlocks     uint64
		hashType      uint32
		hashAlgo      string
		useSalt       bool
		noSuperblock  bool
	}{
		// No superblock tests
		{
			name:          "verify sha256",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       true,
			noSuperblock:  true,
		},
		{
			name:          "verify sha512",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     8,
			hashType:      1,
			hashAlgo:      "sha512",
			useSalt:       false,
			noSuperblock:  true,
		},
		// With superblock tests
		{
			name:          "verify superblock sha256",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       true,
			noSuperblock:  false,
		},
		{
			name:          "verify superblock sha512",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     8,
			hashType:      1,
			hashAlgo:      "sha512",
			useSalt:       false,
			noSuperblock:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, tt.dataBlockSize, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath)

			var salt []byte
			if tt.useSalt {
				salt = []byte("verify-test-salt")
			}

			var rootHash []byte
			if tt.noSuperblock {
				// No superblock mode
				params := &VerityParams{
					HashName:       tt.hashAlgo,
					DataBlockSize:  tt.dataBlockSize,
					HashBlockSize:  tt.hashBlockSize,
					DataBlocks:     tt.numBlocks,
					HashType:       tt.hashType,
					Salt:           salt,
					SaltSize:       uint16(len(salt)),
					HashAreaOffset: 0,
					NoSuperblock:   true,
				}

				var err error
				rootHash, err = HighLevelCreate(params, dataPath, hashPath)
				if err != nil {
					t.Fatalf("HighLevelCreate failed: %v", err)
				}

				t.Logf("Created hash tree with root hash: %x", rootHash)

				err = HighLevelVerify(params, dataPath, hashPath, rootHash)
				if err != nil {
					t.Errorf("HighLevelVerify failed: %v", err)
				} else {
					t.Logf("✓ Go verification successful")
				}

				err = VerifyParams(params, dataPath, hashPath, rootHash, true)
				if err != nil {
					t.Errorf("VerifyParams with checkHash=true failed: %v", err)
				} else {
					t.Logf("✓ VerifyParams verification successful")
				}
			} else {
				// With superblock mode
				uuidStr, err := GenerateUUID()
				if err != nil {
					t.Fatalf("GenerateUUID failed: %v", err)
				}

				params := &VerityParams{
					HashName:       tt.hashAlgo,
					DataBlockSize:  tt.dataBlockSize,
					HashBlockSize:  tt.hashBlockSize,
					DataBlocks:     tt.numBlocks,
					HashType:       tt.hashType,
					Salt:           salt,
					SaltSize:       uint16(len(salt)),
					HashAreaOffset: uint64(tt.hashBlockSize),
					NoSuperblock:   false,
				}

				parsedUUID, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID[:])

				// Write superblock
				hashFile, err := os.OpenFile(hashPath, os.O_RDWR, 0)
				if err != nil {
					t.Fatalf("Failed to open hash file: %v", err)
				}
				err = WriteSuperblock(hashFile, 0, uuidStr, params)
				hashFile.Close()
				if err != nil {
					t.Fatalf("WriteSuperblock failed: %v", err)
				}

				// Create hash tree
				creator, err := NewCreator(params, dataPath, hashPath)
				if err != nil {
					t.Fatalf("NewCreator failed: %v", err)
				}
				rootHash, err = creator.Create()
				if err != nil {
					t.Fatalf("Creator.Create failed: %v", err)
				}

				t.Logf("Created hash tree with superblock, root hash: %x", rootHash)

				err = HighLevelVerify(params, dataPath, hashPath, rootHash)
				if err != nil {
					t.Errorf("HighLevelVerify failed: %v", err)
				} else {
					t.Logf("✓ Go verification successful")
				}

				err = VerifyParams(params, dataPath, hashPath, rootHash, true)
				if err != nil {
					t.Errorf("VerifyParams with checkHash=true failed: %v", err)
				} else {
					t.Logf("✓ VerifyParams verification successful")
				}
			}
		})
	}
}

func TestCrossVerificationWithVeritysetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping cross-verification test")
	}

	tests := []struct {
		name          string
		dataBlockSize uint32
		hashBlockSize uint32
		numBlocks     uint64
		hashType      uint32
		hashAlgo      string
		useSalt       bool
		noSuperblock  bool
	}{
		// No superblock tests
		{
			name:          "cross-verify sha256 no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       false,
			noSuperblock:  true,
		},
		{
			name:          "cross-verify sha256 with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       true,
			noSuperblock:  true,
		},
		{
			name:          "cross-verify sha512 no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     8,
			hashType:      1,
			hashAlgo:      "sha512",
			useSalt:       false,
			noSuperblock:  true,
		},
		{
			name:          "cross-verify sha512 with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     8,
			hashType:      1,
			hashAlgo:      "sha512",
			useSalt:       true,
			noSuperblock:  true,
		},
		{
			name:          "cross-verify sha1 no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     8,
			hashType:      1,
			hashAlgo:      "sha1",
			useSalt:       false,
			noSuperblock:  true,
		},
		{
			name:          "cross-verify sha1 with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     8,
			hashType:      1,
			hashAlgo:      "sha1",
			useSalt:       true,
			noSuperblock:  true,
		},
		// With superblock tests
		{
			name:          "cross-verify superblock sha256 no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       false,
			noSuperblock:  false,
		},
		{
			name:          "cross-verify superblock sha256 with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       true,
			noSuperblock:  false,
		},
		{
			name:          "cross-verify superblock sha512 no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     8,
			hashType:      1,
			hashAlgo:      "sha512",
			useSalt:       false,
			noSuperblock:  false,
		},
		{
			name:          "cross-verify superblock sha1 with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     8,
			hashType:      1,
			hashAlgo:      "sha1",
			useSalt:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, tt.dataBlockSize, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPathGo := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathGo)

			hashPathVeritysetup := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathVeritysetup)

			var salt []byte
			saltArgs := []string{"--salt", "-"}
			if tt.useSalt {
				salt = []byte("cross-verify-salt")
				saltHex := hex.EncodeToString(salt)
				saltArgs = []string{"--salt", saltHex}
			}

			params := &VerityParams{
				HashName:       tt.hashAlgo,
				DataBlockSize:  tt.dataBlockSize,
				HashBlockSize:  tt.hashBlockSize,
				DataBlocks:     tt.numBlocks,
				HashType:       tt.hashType,
				Salt:           salt,
				SaltSize:       uint16(len(salt)),
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			t.Run("go_creates", func(t *testing.T) {
				rootHashGo, err := HighLevelCreate(params, dataPath, hashPathGo)
				if err != nil {
					t.Fatalf("Go HighLevelCreate failed: %v", err)
				}

				args := []string{
					"format",
					dataPath,
					hashPathVeritysetup,
					"--hash", tt.hashAlgo,
					"--data-block-size", fmt.Sprintf("%d", tt.dataBlockSize),
					"--hash-block-size", fmt.Sprintf("%d", tt.hashBlockSize),
				}
				args = append(args, saltArgs...)

				cmd := exec.Command("veritysetup", args...)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("veritysetup format failed: %v\nOutput: %s", err, string(output))
				}

				rootHashC := extractRootHash(t, string(output))
				rootHashCBytes, err := hex.DecodeString(rootHashC)
				if err != nil {
					t.Fatalf("failed to decode veritysetup root hash: %v", err)
				}

				if !bytes.Equal(rootHashGo, rootHashCBytes) {
					t.Errorf("Root hash mismatch:\nGo:          %x\nveritysetup: %x",
						rootHashGo, rootHashCBytes)
				} else {
					t.Logf("✓ Root hash match: %x", rootHashGo)
				}
			})

			t.Run("veritysetup_creates_go_verifies", func(t *testing.T) {
				args := []string{
					"format",
					dataPath,
					hashPathVeritysetup,
					"--hash", tt.hashAlgo,
					"--data-block-size", fmt.Sprintf("%d", tt.dataBlockSize),
					"--hash-block-size", fmt.Sprintf("%d", tt.hashBlockSize),
				}
				args = append(args, saltArgs...)

				cmd := exec.Command("veritysetup", args...)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("veritysetup format failed: %v\nOutput: %s", err, string(output))
				}

				rootHashC := extractRootHash(t, string(output))
				rootHashCBytes, err := hex.DecodeString(rootHashC)
				if err != nil {
					t.Fatalf("failed to decode veritysetup root hash: %v", err)
				}

				t.Logf("veritysetup created hash tree with root hash: %x", rootHashCBytes)

				hashContent, err := os.ReadFile(hashPathVeritysetup)
				if err != nil {
					t.Fatalf("Failed to read veritysetup hash file: %v", err)
				}

				superblockSize := int(tt.hashBlockSize)
				if len(hashContent) > superblockSize {
					hashTreeOnly := hashContent[superblockSize:]
					hashPathStripped := createTestHashFile(t, int64(len(hashTreeOnly)))
					defer os.Remove(hashPathStripped)

					err = os.WriteFile(hashPathStripped, hashTreeOnly, 0644)
					if err != nil {
						t.Fatalf("Failed to write stripped hash file: %v", err)
					}

					err = HighLevelVerify(params, dataPath, hashPathStripped, rootHashCBytes)
					if err != nil {
						t.Errorf("Go failed to verify veritysetup hash tree: %v", err)
					} else {
						t.Logf("✓ Go successfully verified veritysetup hash tree")
					}
				} else {
					t.Logf("⚠ Hash file too small, skipping verification")
				}
			})

			t.Run("go_creates_go_verifies", func(t *testing.T) {
				rootHashGo, err := HighLevelCreate(params, dataPath, hashPathGo)
				if err != nil {
					t.Fatalf("Go HighLevelCreate failed: %v", err)
				}

				err = HighLevelVerify(params, dataPath, hashPathGo, rootHashGo)
				if err != nil {
					t.Errorf("Go failed to verify its own hash tree: %v", err)
				} else {
					t.Logf("✓ Go successfully verified its own hash tree")
				}
			})
		})
	}
}

func TestDataCorruptionDetection(t *testing.T) {
	tests := []struct {
		name      string
		hashAlgo  string
		numBlocks uint64
		useSalt   bool
	}{
		{
			name:      "sha256 corruption detection no salt",
			hashAlgo:  "sha256",
			numBlocks: 16,
			useSalt:   false,
		},
		{
			name:      "sha256 corruption detection with salt",
			hashAlgo:  "sha256",
			numBlocks: 16,
			useSalt:   true,
		},
		{
			name:      "sha512 corruption detection",
			hashAlgo:  "sha512",
			numBlocks: 8,
			useSalt:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath)

			var salt []byte
			if tt.useSalt {
				salt = []byte("corruption-test-salt")
			}

			params := &VerityParams{
				HashName:       tt.hashAlgo,
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           salt,
				SaltSize:       uint16(len(salt)),
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			rootHash, err := HighLevelCreate(params, dataPath, hashPath)
			if err != nil {
				t.Fatalf("HighLevelCreate failed: %v", err)
			}

			err = HighLevelVerify(params, dataPath, hashPath, rootHash)
			if err != nil {
				t.Fatalf("Initial verification failed: %v", err)
			}
			t.Logf("✓ Initial verification successful")

			dataFile, err := os.OpenFile(dataPath, os.O_RDWR, 0)
			if err != nil {
				t.Fatalf("Failed to open data file: %v", err)
			}
			_, err = dataFile.WriteAt([]byte{0xFF, 0xFF, 0xFF, 0xFF}, 0)
			dataFile.Close()
			if err != nil {
				t.Fatalf("Failed to corrupt data: %v", err)
			}

			err = HighLevelVerify(params, dataPath, hashPath, rootHash)
			if err == nil {
				t.Error("Verification should fail with corrupted data")
			} else {
				t.Logf("✓ Correctly detected data corruption: %v", err)
			}

			dataPath2, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath2)
			hashPath2 := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath2)

			rootHash2, _ := HighLevelCreate(params, dataPath2, hashPath2)

			dataFile2, _ := os.OpenFile(dataPath2, os.O_RDWR, 0)
			middleOffset := int64(tt.numBlocks/2) * 4096
			dataFile2.WriteAt([]byte{0xAA, 0xBB, 0xCC, 0xDD}, middleOffset)
			dataFile2.Close()

			err = HighLevelVerify(params, dataPath2, hashPath2, rootHash2)
			if err == nil {
				t.Error("Verification should fail with corrupted middle block")
			} else {
				t.Logf("✓ Correctly detected middle block corruption: %v", err)
			}
		})
	}
}

func TestHashTreeCorruptionDetection(t *testing.T) {
	tests := []struct {
		name      string
		hashAlgo  string
		numBlocks uint64
	}{
		{
			name:      "sha256 hash tree corruption",
			hashAlgo:  "sha256",
			numBlocks: 16,
		},
		{
			name:      "sha512 hash tree corruption",
			hashAlgo:  "sha512",
			numBlocks: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath)

			params := &VerityParams{
				HashName:       tt.hashAlgo,
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           []byte("hash-corruption-test"),
				SaltSize:       20,
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			rootHash, err := HighLevelCreate(params, dataPath, hashPath)
			if err != nil {
				t.Fatalf("HighLevelCreate failed: %v", err)
			}

			// Verify original
			err = HighLevelVerify(params, dataPath, hashPath, rootHash)
			if err != nil {
				t.Fatalf("Initial verification failed: %v", err)
			}
			t.Logf("✓ Initial verification successful")

			// Corrupt hash tree
			hashFile, err := os.OpenFile(hashPath, os.O_RDWR, 0)
			if err != nil {
				t.Fatalf("Failed to open hash file: %v", err)
			}
			_, err = hashFile.WriteAt([]byte{0xFF, 0xFF, 0xFF, 0xFF}, 100)
			hashFile.Close()
			if err != nil {
				t.Fatalf("Failed to corrupt hash tree: %v", err)
			}

			err = HighLevelVerify(params, dataPath, hashPath, rootHash)
			if err == nil {
				t.Error("Verification should fail with corrupted hash tree")
			} else {
				t.Logf("✓ Correctly detected hash tree corruption: %v", err)
			}
		})
	}
}

func TestRootHashMismatch(t *testing.T) {
	dataPath, _ := createTestDataFile(t, 4096, 16)
	defer os.Remove(dataPath)

	hashPath := createTestHashFile(t, int64(4096*32))
	defer os.Remove(hashPath)

	params := &VerityParams{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataBlocks:     16,
		HashType:       1,
		Salt:           []byte("mismatch-test"),
		SaltSize:       13,
		HashAreaOffset: 0,
		NoSuperblock:   true,
	}

	_, err := HighLevelCreate(params, dataPath, hashPath)
	if err != nil {
		t.Fatalf("HighLevelCreate failed: %v", err)
	}

	wrongRootHash := make([]byte, 32)
	for i := range wrongRootHash {
		wrongRootHash[i] = 0xFF
	}

	err = HighLevelVerify(params, dataPath, hashPath, wrongRootHash)
	if err == nil {
		t.Error("Verification should fail with wrong root hash")
	} else {
		t.Logf("✓ Correctly detected root hash mismatch: %v", err)
	}
}

func TestBoundaryConditions(t *testing.T) {
	tests := []struct {
		name        string
		numBlocks   uint64
		shouldError bool
		description string
	}{
		{
			name:        "single block",
			numBlocks:   1,
			shouldError: false,
			description: "Minimum valid data blocks",
		},
		{
			name:        "two blocks",
			numBlocks:   2,
			shouldError: false,
			description: "Small dataset",
		},
		{
			name:        "large dataset",
			numBlocks:   512,
			shouldError: false,
			description: "Large dataset requiring multiple hash levels",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*4))
			defer os.Remove(hashPath)

			params := &VerityParams{
				HashName:       "sha256",
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     tt.numBlocks,
				HashType:       1,
				Salt:           []byte("boundary-test"),
				SaltSize:       13,
				HashAreaOffset: 0,
				NoSuperblock:   true,
			}

			rootHash, err := HighLevelCreate(params, dataPath, hashPath)
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("HighLevelCreate failed for %s: %v", tt.description, err)
			}

			err = HighLevelVerify(params, dataPath, hashPath, rootHash)
			if err != nil {
				t.Errorf("Verification failed for %s: %v", tt.description, err)
			} else {
				t.Logf("✓ %s: %d blocks verified successfully", tt.description, tt.numBlocks)
			}
		})
	}
}
