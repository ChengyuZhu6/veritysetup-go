package verity

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
)

type mockReaderAt struct {
	data []byte
	err  error
}

func (m *mockReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	if off < 0 || off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n = copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

type mockWriterAt struct {
	data []byte
	err  error
}

func (m *mockWriterAt) WriteAt(p []byte, off int64) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if int(off)+len(p) > len(m.data) {
		return 0, io.ErrShortWrite
	}
	n = copy(m.data[off:], p)
	return n, nil
}

func createValidSuperblock(t *testing.T) *VeritySuperblock {
	t.Helper()
	sb := DefaultVeritySuperblock()

	testUUID := uuid.New()
	copy(sb.UUID[:], testUUID[:])

	sb.DataBlocks = 1024
	sb.SaltSize = 32
	for i := 0; i < 32; i++ {
		sb.Salt[i] = byte(i)
	}

	return &sb
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

func TestReadSuperblock(t *testing.T) {
	tests := []struct {
		name      string
		setupData func() (io.ReaderAt, uint64)
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid superblock at offset 0",
			setupData: func() (io.ReaderAt, uint64) {
				sb := createValidSuperblock(t)
				data, err := sb.Serialize()
				if err != nil {
					t.Fatalf("failed to serialize superblock: %v", err)
				}
				if len(data) < VeritySuperblockSize {
					data = append(data, make([]byte, VeritySuperblockSize-len(data))...)
				}
				return &mockReaderAt{data: data}, 0
			},
			wantErr: false,
		},
		{
			name: "valid superblock at offset 512",
			setupData: func() (io.ReaderAt, uint64) {
				sb := createValidSuperblock(t)
				data, err := sb.Serialize()
				if err != nil {
					t.Fatalf("failed to serialize superblock: %v", err)
				}
				paddedData := make([]byte, 512+VeritySuperblockSize)
				copy(paddedData[512:], data)
				return &mockReaderAt{data: paddedData}, 512
			},
			wantErr: false,
		},
		{
			name: "unaligned offset",
			setupData: func() (io.ReaderAt, uint64) {
				return &mockReaderAt{data: make([]byte, 1024)}, 100
			},
			wantErr: true,
			errMsg:  "not 512-byte aligned",
		},
		{
			name: "superblock with empty UUID",
			setupData: func() (io.ReaderAt, uint64) {
				sb := DefaultVeritySuperblock()
				sb.DataBlocks = 1024
				data, err := sb.Serialize()
				if err != nil {
					t.Fatalf("failed to serialize superblock: %v", err)
				}
				return &mockReaderAt{data: data}, 0
			},
			wantErr: true,
			errMsg:  "missing UUID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, offset := tt.setupData()
			sb, err := ReadSuperblock(reader, offset)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ReadSuperblock() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ReadSuperblock() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("ReadSuperblock() unexpected error = %v", err)
				return
			}

			if sb == nil {
				t.Error("ReadSuperblock() returned nil superblock")
			}
		})
	}
}

func TestWriteSuperblock(t *testing.T) {
	tests := []struct {
		name      string
		setupTest func() (*VeritySuperblock, io.WriterAt, uint64)
		wantErr   bool
		errMsg    string
	}{
		{
			name: "write at offset 0",
			setupTest: func() (*VeritySuperblock, io.WriterAt, uint64) {
				sb := createValidSuperblock(t)
				writer := &mockWriterAt{data: make([]byte, 1024)}
				return sb, writer, 0
			},
			wantErr: false,
		},
		{
			name: "write at offset 512",
			setupTest: func() (*VeritySuperblock, io.WriterAt, uint64) {
				sb := createValidSuperblock(t)
				writer := &mockWriterAt{data: make([]byte, 2048)}
				return sb, writer, 512
			},
			wantErr: false,
		},
		{
			name: "unaligned offset",
			setupTest: func() (*VeritySuperblock, io.WriterAt, uint64) {
				sb := createValidSuperblock(t)
				writer := &mockWriterAt{data: make([]byte, 1024)}
				return sb, writer, 100
			},
			wantErr: true,
			errMsg:  "not 512-byte aligned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb, writer, offset := tt.setupTest()
			err := sb.WriteSuperblock(writer, offset)

			if tt.wantErr {
				if err == nil {
					t.Errorf("WriteSuperblock() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("WriteSuperblock() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("WriteSuperblock() unexpected error = %v", err)
			}
		})
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	original := createValidSuperblock(t)

	buffer := make([]byte, 2048)
	writer := &mockWriterAt{data: buffer}

	offset := uint64(512)
	if err := original.WriteSuperblock(writer, offset); err != nil {
		t.Fatalf("WriteSuperblock() failed: %v", err)
	}

	reader := &mockReaderAt{data: buffer}
	readBack, err := ReadSuperblock(reader, offset)
	if err != nil {
		t.Fatalf("ReadSuperblock() failed: %v", err)
	}

	if !bytes.Equal(original.Signature[:], readBack.Signature[:]) {
		t.Error("Signature mismatch")
	}
	if original.Version != readBack.Version {
		t.Errorf("Version mismatch: got %d, want %d", readBack.Version, original.Version)
	}
	if original.HashType != readBack.HashType {
		t.Errorf("HashType mismatch: got %d, want %d", readBack.HashType, original.HashType)
	}
	if !bytes.Equal(original.UUID[:], readBack.UUID[:]) {
		t.Error("UUID mismatch")
	}
	if !bytes.Equal(original.Algorithm[:], readBack.Algorithm[:]) {
		t.Error("Algorithm mismatch")
	}
	if original.DataBlockSize != readBack.DataBlockSize {
		t.Errorf("DataBlockSize mismatch: got %d, want %d", readBack.DataBlockSize, original.DataBlockSize)
	}
	if original.HashBlockSize != readBack.HashBlockSize {
		t.Errorf("HashBlockSize mismatch: got %d, want %d", readBack.HashBlockSize, original.HashBlockSize)
	}
	if original.DataBlocks != readBack.DataBlocks {
		t.Errorf("DataBlocks mismatch: got %d, want %d", readBack.DataBlocks, original.DataBlocks)
	}
	if original.SaltSize != readBack.SaltSize {
		t.Errorf("SaltSize mismatch: got %d, want %d", readBack.SaltSize, original.SaltSize)
	}
	if !bytes.Equal(original.Salt[:], readBack.Salt[:]) {
		t.Error("Salt mismatch")
	}
}

func TestBuildSuperblockFromParams(t *testing.T) {
	tests := []struct {
		name    string
		params  *VerityParams
		wantErr bool
		errMsg  string
		verify  func(*testing.T, *VeritySuperblock)
	}{
		{
			name:    "nil params",
			params:  nil,
			wantErr: true,
			errMsg:  "nil params",
		},
		{
			name: "valid params with sha256",
			params: &VerityParams{
				HashName:      "sha256",
				DataBlockSize: 4096,
				HashBlockSize: 4096,
				DataBlocks:    1000,
				HashType:      1,
				Salt:          make([]byte, 32),
				SaltSize:      32,
				UUID:          uuid.New(),
			},
			wantErr: false,
			verify: func(t *testing.T, sb *VeritySuperblock) {
				if sb.Version != 1 {
					t.Errorf("Version = %d, want 1", sb.Version)
				}
				if sb.DataBlockSize != 4096 {
					t.Errorf("DataBlockSize = %d, want 4096", sb.DataBlockSize)
				}
				if sb.HashBlockSize != 4096 {
					t.Errorf("HashBlockSize = %d, want 4096", sb.HashBlockSize)
				}
				if sb.DataBlocks != 1000 {
					t.Errorf("DataBlocks = %d, want 1000", sb.DataBlocks)
				}
				if sb.SaltSize != 32 {
					t.Errorf("SaltSize = %d, want 32", sb.SaltSize)
				}
				algo := sb.algorithmString()
				if algo != "sha256" {
					t.Errorf("Algorithm = %q, want %q", algo, "sha256")
				}
			},
		},
		{
			name: "valid params with sha512",
			params: &VerityParams{
				HashName:      "sha512",
				DataBlockSize: 4096,
				HashBlockSize: 4096,
				DataBlocks:    500,
				HashType:      1,
				Salt:          make([]byte, 64),
				SaltSize:      64,
				UUID:          uuid.New(),
			},
			wantErr: false,
			verify: func(t *testing.T, sb *VeritySuperblock) {
				algo := sb.algorithmString()
				if algo != "sha512" {
					t.Errorf("Algorithm = %q, want %q", algo, "sha512")
				}
			},
		},
		{
			name: "valid params with empty UUID",
			params: &VerityParams{
				HashName:      "sha256",
				DataBlockSize: 4096,
				HashBlockSize: 4096,
				DataBlocks:    1000,
				HashType:      1,
				Salt:          make([]byte, 32),
				SaltSize:      32,
				UUID:          [16]byte{}, // Empty UUID is valid
			},
			wantErr: false,
			verify: func(t *testing.T, sb *VeritySuperblock) {
				if sb.UUID != ([16]byte{}) {
					t.Error("UUID should be empty")
				}
			},
		},
		{
			name: "invalid data block size",
			params: &VerityParams{
				HashName:      "sha256",
				DataBlockSize: 1000, // Not power of 2
				HashBlockSize: 4096,
				DataBlocks:    100,
				HashType:      1,
				Salt:          make([]byte, 32),
				SaltSize:      32,
				UUID:          uuid.New(),
			},
			wantErr: true,
			errMsg:  "invalid block sizes",
		},
		{
			name: "invalid hash block size",
			params: &VerityParams{
				HashName:      "sha256",
				DataBlockSize: 4096,
				HashBlockSize: 3000, // Not power of 2
				DataBlocks:    100,
				HashType:      1,
				Salt:          make([]byte, 32),
				SaltSize:      32,
				UUID:          uuid.New(),
			},
			wantErr: true,
			errMsg:  "invalid block sizes",
		},
		{
			name: "unsupported hash type",
			params: &VerityParams{
				HashName:      "sha256",
				DataBlockSize: 4096,
				HashBlockSize: 4096,
				DataBlocks:    100,
				HashType:      99, // Invalid
				Salt:          make([]byte, 32),
				SaltSize:      32,
				UUID:          uuid.New(),
			},
			wantErr: true,
			errMsg:  "unsupported hash type",
		},
		{
			name: "salt size mismatch",
			params: &VerityParams{
				HashName:      "sha256",
				DataBlockSize: 4096,
				HashBlockSize: 4096,
				DataBlocks:    100,
				HashType:      1,
				Salt:          make([]byte, 32),
				SaltSize:      64, // Mismatch
				UUID:          uuid.New(),
			},
			wantErr: true,
			errMsg:  "salt size mismatch",
		},
		{
			name: "salt too large",
			params: &VerityParams{
				HashName:      "sha256",
				DataBlockSize: 4096,
				HashBlockSize: 4096,
				DataBlocks:    100,
				HashType:      1,
				Salt:          make([]byte, 300),
				SaltSize:      300, // > MaxSaltSize
				UUID:          uuid.New(),
			},
			wantErr: true,
			errMsg:  "salt too large",
		},
		{
			name: "empty hash algorithm",
			params: &VerityParams{
				HashName:      "",
				DataBlockSize: 4096,
				HashBlockSize: 4096,
				DataBlocks:    100,
				HashType:      1,
				Salt:          make([]byte, 32),
				SaltSize:      32,
				UUID:          uuid.New(),
			},
			wantErr: true,
			errMsg:  "hash algorithm required",
		},
		{
			name: "unsupported hash algorithm",
			params: &VerityParams{
				HashName:      "md5",
				DataBlockSize: 4096,
				HashBlockSize: 4096,
				DataBlocks:    100,
				HashType:      1,
				Salt:          make([]byte, 32),
				SaltSize:      32,
				UUID:          uuid.New(),
			},
			wantErr: true,
			errMsg:  "not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb, err := BuildSuperblockFromParams(tt.params)

			if tt.wantErr {
				if err == nil {
					t.Errorf("BuildSuperblockFromParams() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("BuildSuperblockFromParams() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("BuildSuperblockFromParams() unexpected error = %v", err)
				return
			}

			if sb == nil {
				t.Error("BuildSuperblockFromParams() returned nil superblock")
				return
			}

			if string(sb.Signature[:]) != VeritySignature {
				t.Error("Invalid signature in built superblock")
			}

			if tt.verify != nil {
				tt.verify(t, sb)
			}
		})
	}
}

func TestAdoptParamsFromSuperblock(t *testing.T) {
	tests := []struct {
		name      string
		setupTest func() (*VerityParams, *VeritySuperblock, uint64)
		wantErr   bool
		errMsg    string
		verify    func(*testing.T, *VerityParams)
	}{
		{
			name: "nil params",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				return nil, sb, 0
			},
			wantErr: true,
			errMsg:  "nil params",
		},
		{
			name: "nil superblock",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				params := &VerityParams{}
				return params, nil, 0
			},
			wantErr: true,
			errMsg:  "nil params or superblock",
		},
		{
			name: "adopt all fields from superblock",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				params := &VerityParams{}
				return params, sb, 1024
			},
			wantErr: false,
			verify: func(t *testing.T, p *VerityParams) {
				if p.HashName != "sha256" {
					t.Errorf("HashName = %q, want %q", p.HashName, "sha256")
				}
				if p.DataBlockSize != 4096 {
					t.Errorf("DataBlockSize = %d, want 4096", p.DataBlockSize)
				}
				if p.HashBlockSize != 4096 {
					t.Errorf("HashBlockSize = %d, want 4096", p.HashBlockSize)
				}
				if p.DataBlocks != 1024 {
					t.Errorf("DataBlocks = %d, want 1024", p.DataBlocks)
				}
				if p.SaltSize != 32 {
					t.Errorf("SaltSize = %d, want 32", p.SaltSize)
				}
				if p.HashAreaOffset != 1024 {
					t.Errorf("HashAreaOffset = %d, want 1024", p.HashAreaOffset)
				}
				if p.NoSuperblock {
					t.Error("NoSuperblock should be false")
				}
			},
		},
		{
			name: "matching params and superblock",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				params := &VerityParams{
					HashName:      "sha256",
					DataBlockSize: 4096,
					HashBlockSize: 4096,
					DataBlocks:    1024,
					HashType:      1,
					Salt:          make([]byte, 32),
					SaltSize:      32,
					UUID:          sb.UUID,
				}
				copy(params.Salt, sb.Salt[:32])
				return params, sb, 512
			},
			wantErr: false,
		},
		{
			name: "adopt from superblock with empty UUID",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := DefaultVeritySuperblock()
				sb.DataBlocks = 1024
				sb.SaltSize = 32
				for i := 0; i < 32; i++ {
					sb.Salt[i] = byte(i)
				}
				// UUID is empty ([16]byte{})
				params := &VerityParams{}
				return params, &sb, 512
			},
			wantErr: false,
			verify: func(t *testing.T, p *VerityParams) {
				if p.UUID != ([16]byte{}) {
					t.Error("UUID should be empty")
				}
			},
		},
		{
			name: "algorithm mismatch",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				params := &VerityParams{
					HashName: "sha512", // Mismatch
				}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "algorithm mismatch",
		},
		{
			name: "data block size mismatch",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				params := &VerityParams{
					DataBlockSize: 8192, // Mismatch
				}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "data block size mismatch",
		},
		{
			name: "hash block size mismatch",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				params := &VerityParams{
					HashBlockSize: 8192, // Mismatch
				}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "hash block size mismatch",
		},
		{
			name: "data blocks mismatch",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				params := &VerityParams{
					DataBlocks: 2048, // Mismatch
				}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "data blocks mismatch",
		},
		{
			name: "salt mismatch",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				params := &VerityParams{
					Salt:     make([]byte, 32),
					SaltSize: 32,
				}
				// Different salt content
				for i := range params.Salt {
					params.Salt[i] = 0xFF
				}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "salt mismatch",
		},
		{
			name: "UUID mismatch",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				params := &VerityParams{
					UUID: uuid.New(), // Different UUID
				}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "UUID mismatch",
		},
		{
			name: "invalid superblock signature",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				sb.Signature = [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				params := &VerityParams{}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "invalid superblock signature",
		},
		{
			name: "invalid superblock version",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				sb.Version = 99
				params := &VerityParams{}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "unsupported superblock version",
		},
		{
			name: "unsupported hash type in superblock",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				sb.HashType = 99
				params := &VerityParams{}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "unsupported hash type",
		},
		{
			name: "invalid block size in superblock",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				sb.DataBlockSize = 1000 // Not valid
				params := &VerityParams{}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "invalid block size",
		},
		{
			name: "salt too large in superblock",
			setupTest: func() (*VerityParams, *VeritySuperblock, uint64) {
				sb := createValidSuperblock(t)
				sb.SaltSize = 300 // > MaxSaltSize
				params := &VerityParams{}
				return params, sb, 0
			},
			wantErr: true,
			errMsg:  "salt too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, sb, offset := tt.setupTest()
			err := AdoptParamsFromSuperblock(params, sb, offset)

			if tt.wantErr {
				if err == nil {
					t.Errorf("AdoptParamsFromSuperblock() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("AdoptParamsFromSuperblock() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("AdoptParamsFromSuperblock() unexpected error = %v", err)
				return
			}

			if tt.verify != nil {
				tt.verify(t, params)
			}
		})
	}
}

func TestBuildAndAdoptRoundTrip(t *testing.T) {
	originalParams := &VerityParams{
		HashName:      "sha256",
		DataBlockSize: 4096,
		HashBlockSize: 4096,
		DataBlocks:    1000,
		HashType:      1,
		Salt:          make([]byte, 32),
		SaltSize:      32,
		UUID:          uuid.New(),
	}
	for i := range originalParams.Salt {
		originalParams.Salt[i] = byte(i)
	}

	sb, err := BuildSuperblockFromParams(originalParams)
	if err != nil {
		t.Fatalf("BuildSuperblockFromParams() failed: %v", err)
	}

	newParams := &VerityParams{}
	if err := AdoptParamsFromSuperblock(newParams, sb, 512); err != nil {
		t.Fatalf("AdoptParamsFromSuperblock() failed: %v", err)
	}

	if newParams.HashName != originalParams.HashName {
		t.Errorf("HashName mismatch: got %q, want %q", newParams.HashName, originalParams.HashName)
	}
	if newParams.DataBlockSize != originalParams.DataBlockSize {
		t.Errorf("DataBlockSize mismatch: got %d, want %d", newParams.DataBlockSize, originalParams.DataBlockSize)
	}
	if newParams.HashBlockSize != originalParams.HashBlockSize {
		t.Errorf("HashBlockSize mismatch: got %d, want %d", newParams.HashBlockSize, originalParams.HashBlockSize)
	}
	if newParams.DataBlocks != originalParams.DataBlocks {
		t.Errorf("DataBlocks mismatch: got %d, want %d", newParams.DataBlocks, originalParams.DataBlocks)
	}
	if newParams.HashType != originalParams.HashType {
		t.Errorf("HashType mismatch: got %d, want %d", newParams.HashType, originalParams.HashType)
	}
	if newParams.SaltSize != originalParams.SaltSize {
		t.Errorf("SaltSize mismatch: got %d, want %d", newParams.SaltSize, originalParams.SaltSize)
	}
	if !bytes.Equal(newParams.Salt, originalParams.Salt) {
		t.Error("Salt mismatch")
	}
	if newParams.UUID != originalParams.UUID {
		t.Error("UUID mismatch")
	}
	if newParams.HashAreaOffset != 512 {
		t.Errorf("HashAreaOffset = %d, want 512", newParams.HashAreaOffset)
	}
	if newParams.NoSuperblock {
		t.Error("NoSuperblock should be false")
	}
}
