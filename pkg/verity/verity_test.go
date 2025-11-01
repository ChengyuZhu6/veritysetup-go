package verity

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/uuid"
)

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
