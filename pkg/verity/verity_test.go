package verity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
	"github.com/google/uuid"
)

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
			result := utils.SelectHashSize(tt.hashName)
			if result != tt.expected {
				t.Errorf("SelectHashSize(%q) = %d, want %d", tt.hashName, result, tt.expected)
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
			result := utils.Uint64MultOverflow(tt.a, tt.b)
			if result != tt.overflow {
				t.Errorf("uint64MultOverflow(%d, %d) = %v, want %v", tt.a, tt.b, result, tt.overflow)
			}
		})
	}
}

func TestWriteSuperblockErrors(t *testing.T) {
	tests := []struct {
		name        string
		params      *VerityParams
		uuid        string
		expectError bool
	}{
		{"nil params", nil, "550e8400-e29b-41d4-a716-446655440000", true},
		{"no superblock", &VerityParams{NoSuperblock: true}, "550e8400-e29b-41d4-a716-446655440000", true},
		{"invalid uuid", &VerityParams{DataBlocks: 100}, "invalid-uuid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "verity-test-*.img")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			var testErr error
			if tt.params == nil {
				testErr = errors.New("verity: nil params")
			} else if tt.params.NoSuperblock {
				testErr = errors.New("verity: device does not use on-disk header")
			} else if tt.uuid == "" {
				testErr = errors.New("verity: UUID required")
			} else {
				parsedUUID, err := uuid.Parse(tt.uuid)
				if err != nil {
					testErr = fmt.Errorf("verity: wrong UUID format: %w", err)
				} else {
					copy(tt.params.UUID[:], parsedUUID[:])
					sb, err := buildSuperblockFromParams(tt.params)
					if err != nil {
						testErr = err
					} else {
						testErr = sb.WriteSuperblock(tmpFile, 0)
					}
				}
			}

			if (testErr != nil) != tt.expectError {
				t.Errorf("WriteSuperblock() error = %v, expectError %v", testErr, tt.expectError)
			}
		})
	}
}

func TestReadVeritySuperblockErrors(t *testing.T) {
	tests := []struct {
		name        string
		params      *VerityParams
		offset      uint64
		expectError bool
	}{
		{"nil params", nil, 0, true},
		{"no superblock", &VerityParams{NoSuperblock: true}, 0, true},
		{"unaligned offset", &VerityParams{}, 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "verity-test-*.img")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			var testErr error
			if tt.params == nil {
				testErr = errors.New("verity: nil params")
			} else if tt.params.NoSuperblock {
				testErr = errors.New("verity: device does not use on-disk header")
			} else if tt.offset%diskSectorSize != 0 {
				testErr = errors.New("verity: unsupported hash offset (not 512-byte aligned)")
			} else {
				sb, err := ReadSuperblock(tmpFile, tt.offset)
				if err != nil {
					testErr = err
				} else {
					testErr = adoptParamsFromSuperblock(tt.params, sb, tt.offset)
				}
			}

			if (testErr != nil) != tt.expectError {
				t.Errorf("ReadVeritySuperblock() error = %v, expectError %v", testErr, tt.expectError)
			}
		})
	}
}

func TestSuperblockRoundTrip(t *testing.T) {
	dataPath, _ := createTestDataFile(t, 4096, 16)
	defer os.Remove(dataPath)

	hashPath := createTestHashFile(t, int64(4096*16*4))
	defer os.Remove(hashPath)

	uuidStr := uuid.New().String()

	salt := []byte("superblock-test")
	params := &VerityParams{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataBlocks:     16,
		HashType:       1,
		Salt:           salt,
		SaltSize:       uint16(len(salt)),
		HashAreaOffset: 0,
		NoSuperblock:   false,
	}

	parsedUUID, _ := uuid.Parse(uuidStr)
	copy(params.UUID[:], parsedUUID[:])

	hashFile, err := os.OpenFile(hashPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("Failed to open hash file: %v", err)
	}

	sb, err := buildSuperblockFromParams(params)
	if err != nil {
		t.Fatalf("buildSuperblockFromParams failed: %v", err)
	}
	err = sb.WriteSuperblock(hashFile, 0)
	hashFile.Close()
	if err != nil {
		t.Fatalf("WriteSuperblock failed: %v", err)
	}

	hashFile2, err := os.Open(hashPath)
	if err != nil {
		t.Fatalf("Failed to open hash file for reading: %v", err)
	}
	defer hashFile2.Close()

	readParams := &VerityParams{}
	sbRead, err := ReadSuperblock(hashFile2, 0)
	if err != nil {
		t.Fatalf("ReadSuperblock failed: %v", err)
	}

	if err := adoptParamsFromSuperblock(readParams, sbRead, 0); err != nil {
		t.Fatalf("adoptParamsFromSuperblock failed: %v", err)
	}

	readUUID, err := sbRead.UUIDString()
	if err != nil {
		t.Fatalf("UUIDString failed: %v", err)
	}

	if strings.ToLower(readUUID) != strings.ToLower(uuidStr) {
		t.Errorf("UUID mismatch: written=%s, read=%s", uuidStr, readUUID)
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
}

func TestVerityCreateWithVeritysetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping integration test")
	}

	tests := []struct {
		name         string
		numBlocks    uint64
		hashAlgo     string
		useSalt      bool
		noSuperblock bool
	}{
		{"basic sha256 no salt", 16, "sha256", false, true},
		{"sha256 with salt", 32, "sha256", true, true},
		{"sha512 no salt", 16, "sha512", false, true},
		{"sha1 with salt", 8, "sha1", true, true},
		{"superblock sha256 no salt", 16, "sha256", false, false},
		{"superblock sha256 with salt", 32, "sha256", true, false},
		{"superblock sha512 no salt", 16, "sha512", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPathGo := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathGo)

			hashPathC := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathC)

			var salt []byte
			saltArgs := []string{"--salt", "-"}
			if tt.useSalt {
				salt = []byte("integration-test-salt")
				saltArgs = []string{"--salt", hex.EncodeToString(salt)}
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
				NoSuperblock:   tt.noSuperblock,
			}

			var rootHashGo []byte
			var err error

			if tt.noSuperblock {
				rootHashGo, err = VerityCreate(params, dataPath, hashPathGo)
				if err != nil {
					t.Fatalf("VerityCreate failed: %v", err)
				}
			} else {
				uuidStr := uuid.New().String()
				params.HashAreaOffset = 4096
				parsedUUID, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID[:])

				hashFile, _ := os.OpenFile(hashPathGo, os.O_RDWR, 0)
				parsedUUID2, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID2[:])
				sb, _ := buildSuperblockFromParams(params)
				sb.WriteSuperblock(hashFile, 0)
				hashFile.Close()

				rootHashGo, err = VerityCreate(params, dataPath, hashPathGo)
				if err != nil {
					t.Fatalf("VerityCreate failed: %v", err)
				}
			}

			args := []string{"format", dataPath, hashPathC, "--hash", tt.hashAlgo,
				"--data-block-size", "4096", "--hash-block-size", "4096"}
			args = append(args, saltArgs...)
			if tt.noSuperblock {
				args = append(args, "--no-superblock")
			}

			cmd := exec.Command("veritysetup", args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("veritysetup format failed: %v\nOutput: %s", err, string(output))
			}

			rootHashC := extractRootHash(t, string(output))
			rootHashCBytes, _ := hex.DecodeString(rootHashC)

			if !bytes.Equal(rootHashGo, rootHashCBytes) {
				t.Errorf("Root hash mismatch:\nGo: %x\nveritysetup: %x", rootHashGo, rootHashCBytes)
			}
		})
	}
}

func TestVerityVerifyWithVeritysetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping integration test")
	}

	tests := []struct {
		name         string
		numBlocks    uint64
		hashAlgo     string
		useSalt      bool
		noSuperblock bool
	}{
		{"verify sha256", 16, "sha256", true, true},
		{"verify sha512", 8, "sha512", false, true},
		{"verify superblock sha256", 16, "sha256", true, false},
		{"verify superblock sha512", 8, "sha512", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPath := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath)

			var salt []byte
			if tt.useSalt {
				salt = []byte("verify-test-salt")
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
				NoSuperblock:   tt.noSuperblock,
			}

			var rootHash []byte
			var err error

			if tt.noSuperblock {
				rootHash, err = VerityCreate(params, dataPath, hashPath)
			} else {
				uuidStr := uuid.New().String()
				params.HashAreaOffset = 4096
				parsedUUID, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID[:])

				hashFile, _ := os.OpenFile(hashPath, os.O_RDWR, 0)
				parsedUUID2, _ := uuid.Parse(uuidStr)
				copy(params.UUID[:], parsedUUID2[:])
				sb, _ := buildSuperblockFromParams(params)
				sb.WriteSuperblock(hashFile, 0)
				hashFile.Close()

				rootHash, err = VerityCreate(params, dataPath, hashPath)
			}

			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			if err := VerityVerify(params, dataPath, hashPath, rootHash); err != nil {
				t.Errorf("VerityVerify failed: %v", err)
			}
		})
	}
}

func TestCrossVerificationWithVeritysetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping cross-verification test")
	}

	tests := []struct {
		name      string
		numBlocks uint64
		hashAlgo  string
		useSalt   bool
	}{
		{"sha256 no salt", 16, "sha256", false},
		{"sha256 with salt", 16, "sha256", true},
		{"sha512 no salt", 8, "sha512", false},
		{"sha512 with salt", 8, "sha512", true},
		{"sha1 no salt", 8, "sha1", false},
		{"sha1 with salt", 8, "sha1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataPath, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath)

			hashPathGo := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathGo)

			hashPathC := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathC)

			var salt []byte
			saltArgs := []string{"--salt", "-"}
			if tt.useSalt {
				salt = []byte("cross-verify-salt")
				saltArgs = []string{"--salt", hex.EncodeToString(salt)}
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

			rootHashGo, _ := VerityCreate(params, dataPath, hashPathGo)

			args := []string{"format", dataPath, hashPathC, "--hash", tt.hashAlgo,
				"--data-block-size", "4096", "--hash-block-size", "4096"}
			args = append(args, saltArgs...)

			cmd := exec.Command("veritysetup", args...)
			output, _ := cmd.CombinedOutput()
			rootHashC := extractRootHash(t, string(output))
			rootHashCBytes, _ := hex.DecodeString(rootHashC)

			if !bytes.Equal(rootHashGo, rootHashCBytes) {
				t.Errorf("Root hash mismatch: Go=%x, veritysetup=%x", rootHashGo, rootHashCBytes)
			}

			hashContent, _ := os.ReadFile(hashPathC)
			if len(hashContent) > 4096 {
				hashTreeOnly := hashContent[4096:]
				hashPathStripped := createTestHashFile(t, int64(len(hashTreeOnly)))
				defer os.Remove(hashPathStripped)
				os.WriteFile(hashPathStripped, hashTreeOnly, 0644)

				if err := VerityVerify(params, dataPath, hashPathStripped, rootHashCBytes); err != nil {
					t.Errorf("Go failed to verify veritysetup hash tree: %v", err)
				}
			}

			if err := VerityVerify(params, dataPath, hashPathGo, rootHashGo); err != nil {
				t.Errorf("Go failed to verify its own hash tree: %v", err)
			}
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
		{"sha256 no salt", "sha256", 16, false},
		{"sha256 with salt", "sha256", 16, true},
		{"sha512", "sha512", 8, true},
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

			rootHash, _ := VerityCreate(params, dataPath, hashPath)

			if err := VerityVerify(params, dataPath, hashPath, rootHash); err != nil {
				t.Fatalf("Initial verification failed: %v", err)
			}

			dataFile, _ := os.OpenFile(dataPath, os.O_RDWR, 0)
			dataFile.WriteAt([]byte{0xFF, 0xFF, 0xFF, 0xFF}, 0)
			dataFile.Close()

			if err := VerityVerify(params, dataPath, hashPath, rootHash); err == nil {
				t.Error("Verification should fail with corrupted data")
			}

			dataPath2, _ := createTestDataFile(t, 4096, tt.numBlocks)
			defer os.Remove(dataPath2)
			hashPath2 := createTestHashFile(t, int64(4096*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPath2)

			rootHash2, _ := VerityCreate(params, dataPath2, hashPath2)

			dataFile2, _ := os.OpenFile(dataPath2, os.O_RDWR, 0)
			dataFile2.WriteAt([]byte{0xAA, 0xBB, 0xCC, 0xDD}, int64(tt.numBlocks/2)*4096)
			dataFile2.Close()

			if err := VerityVerify(params, dataPath2, hashPath2, rootHash2); err == nil {
				t.Error("Verification should fail with corrupted middle block")
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
		{"sha256", "sha256", 16},
		{"sha512", "sha512", 16},
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

			rootHash, _ := VerityCreate(params, dataPath, hashPath)

			if err := VerityVerify(params, dataPath, hashPath, rootHash); err != nil {
				t.Fatalf("Initial verification failed: %v", err)
			}

			hashFile, _ := os.OpenFile(hashPath, os.O_RDWR, 0)
			hashFile.WriteAt([]byte{0xFF, 0xFF, 0xFF, 0xFF}, 100)
			hashFile.Close()

			if err := VerityVerify(params, dataPath, hashPath, rootHash); err == nil {
				t.Error("Verification should fail with corrupted hash tree")
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

	_, err := VerityCreate(params, dataPath, hashPath)
	if err != nil {
		t.Fatalf("VerityCreate failed: %v", err)
	}

	wrongRootHash := make([]byte, 32)
	for i := range wrongRootHash {
		wrongRootHash[i] = 0xFF
	}

	err = VerityVerify(params, dataPath, hashPath, wrongRootHash)
	if err == nil {
		t.Error("Verification should fail with wrong root hash")
	}
}

func TestBoundaryConditions(t *testing.T) {
	tests := []struct {
		name      string
		numBlocks uint64
	}{
		{"single block", 1},
		{"two blocks", 2},
		{"large dataset", 512},
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

			rootHash, err := VerityCreate(params, dataPath, hashPath)
			if err != nil {
				t.Fatalf("VerityCreate failed: %v", err)
			}

			if err := VerityVerify(params, dataPath, hashPath, rootHash); err != nil {
				t.Errorf("Verification failed: %v", err)
			}
		})
	}
}
