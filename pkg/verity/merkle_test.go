package verity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func testCreateAndVerify(t *testing.T, p *VerityParams, dataPath, hashPath string) error {
	t.Helper()

	vh := NewVerityHash(p, dataPath, hashPath, nil)
	rootHash := make([]byte, vh.hashFunc.Size())
	if err := vh.Create(); err != nil {
		return fmt.Errorf("hash creation failed: %w", err)
	}

	copy(rootHash, vh.rootHash)

	vh = NewVerityHash(p, dataPath, hashPath, rootHash)
	if err := vh.Verify(); err != nil {
		return fmt.Errorf("hash verification failed: %w", err)
	}
	return nil
}

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
			params:   SetupVerityTestParams(1 * 1024 * 1024),
			wantErr:  false,
		},
		{
			name:     "medium file (10MB)",
			dataSize: 10 * 1024 * 1024,
			params:   SetupVerityTestParams(10 * 1024 * 1024),
			wantErr:  false,
		},
		{
			name:     "SHA512 with 4K blocks",
			dataSize: 1 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha512",
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     (1 * 1024 * 1024) / 4096,
				HashType:       1,
				Salt:           []byte("test-salt"),
				SaltSize:       uint16(len([]byte("test-salt"))),
				HashAreaOffset: 8192,
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
				DataBlocks:     (1 * 1024 * 1024) / 1024,
				HashType:       1,
				Salt:           []byte("test-salt"),
				SaltSize:       uint16(len([]byte("test-salt"))),
				HashAreaOffset: 8192,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			if err := SetupTestData(dataPath, hashPath, tt.params, tt.dataSize); err != nil {
				t.Fatalf("setupTestData failed: %v", err)
			}

			if err := testCreateAndVerify(t, tt.params, dataPath, hashPath); (err != nil) != tt.wantErr {
				t.Errorf("testCreateAndVerify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerityHashCorruption(t *testing.T) {
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.img")
	hashPath := filepath.Join(tmpDir, "hash.img")
	dataSize := uint64(1024 * 1024)
	p := SetupVerityTestParams(dataSize)

	if err := SetupTestData(dataPath, hashPath, p, dataSize); err != nil {
		t.Fatalf("setupTestData failed: %v", err)
	}

	vh := NewVerityHash(p, dataPath, hashPath, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("Failed to create initial hash: %v", err)
	}
	rootHash := make([]byte, vh.hashFunc.Size())
	copy(rootHash, vh.rootHash)

	if err := CorruptFile(dataPath, 1000); err != nil {
		t.Fatalf("Failed to corrupt data: %v", err)
	}

	vh = NewVerityHash(p, dataPath, hashPath, rootHash)
	if err := vh.Verify(); err == nil {
		t.Error("Verification should fail with corrupted data")
	}
}

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
			params:   SetupVerityTestParams(1024 * 1024),
		},
		{
			name:     "1MB file with SHA512",
			dataSize: 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha512",
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     (1024 * 1024) / 4096,
				HashType:       1,
				Salt:           []byte("test-salt"),
				SaltSize:       uint16(len([]byte("test-salt"))),
				HashAreaOffset: 8192,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			if err := SetupTestData(dataPath, hashPath, tt.params, tt.dataSize); err != nil {
				t.Fatalf("setupTestData failed: %v", err)
			}

			vh := NewVerityHash(tt.params, dataPath, hashPath, nil)
			if err := vh.Create(); err != nil {
				t.Fatalf("our implementation create failed: %v", err)
			}
			veritysetupHashPath := hashPath + ".verity"
			if _, err := GetVeritySetupRootHash(dataPath, hashPath, tt.params); err != nil {
				t.Fatalf("veritysetup failed: %v", err)
			}
			ourHashContent, err := os.ReadFile(hashPath)
			if err != nil {
				t.Fatalf("read our hash: %v", err)
			}
			vsHashContent, err := os.ReadFile(veritysetupHashPath)
			if err != nil {
				t.Fatalf("read veritysetup hash: %v", err)
			}
			// Compare superblock first
			ourSuperblock := ourHashContent[:VeritySuperblockSize]
			vsSuperblock := vsHashContent[:VeritySuperblockSize]
			if fmt.Sprintf("%x", ourSuperblock) != fmt.Sprintf("%x", vsSuperblock) {
				t.Errorf("superblock mismatch")
			}

			// Compare hash tree data
			ourHashData := ourHashContent[tt.params.HashAreaOffset:]
			vsHashData := vsHashContent[tt.params.HashAreaOffset:]
			if fmt.Sprintf("%x", ourHashData) != fmt.Sprintf("%x", vsHashData) {
				t.Errorf("hash file content mismatch from offset %d", tt.params.HashAreaOffset)
			}
		})
	}
}

func TestNoSuperblockModeLayout(t *testing.T) {
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.img")
	hashPath := filepath.Join(tmpDir, "hash.img")
	dataSize := uint64(1 * 1024 * 1024)

	p := SetupVerityTestParams(dataSize)
	p.NoSuperblock = true
	p.HashAreaOffset = 2 * uint64(p.HashBlockSize)

	if err := SetupTestData(dataPath, hashPath, p, dataSize); err != nil {
		t.Fatalf("setupTestData failed: %v", err)
	}

	vh := NewVerityHash(p, dataPath, hashPath, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	pre := make([]byte, p.HashAreaOffset)
	f, err := os.Open(hashPath)
	if err != nil {
		t.Fatalf("open hash: %v", err)
	}
	defer f.Close()
	if _, err := f.ReadAt(pre, 0); err != nil {
		t.Fatalf("read pre-offset: %v", err)
	}
	for i, b := range pre {
		if b != 0 {
			t.Fatalf("expected zero before HashAreaOffset at byte %d", i)
		}
	}

	hashSize := uint32(vh.hashFunc.Size())
	hashesPerBlock := p.HashBlockSize / hashSize
	blockIdx := uint64(0) / uint64(hashesPerBlock)
	intra := (uint64(0) % uint64(hashesPerBlock)) * uint64(hashSize)
	offset := p.HashAreaOffset + blockIdx*uint64(p.HashBlockSize) + intra

	dataF, err := os.Open(dataPath)
	if err != nil {
		t.Fatalf("open data: %v", err)
	}
	defer dataF.Close()
	dataBlock, err := readBlock(dataF, 0, p.DataBlockSize)
	if err != nil {
		t.Fatalf("read data block: %v", err)
	}
	leaf, err := vh.verifyHashBlock(dataBlock, p.Salt)
	if err != nil {
		t.Fatalf("compute leaf: %v", err)
	}

	got, err := readBlock(f, offset, hashSize)
	if err != nil {
		t.Fatalf("read stored leaf: %v", err)
	}
	if fmt.Sprintf("%x", got) != fmt.Sprintf("%x", leaf) {
		t.Fatalf("leaf mismatch at offset %d", offset)
	}
}

func TestAgainstVeritySetupPerLevel(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping per-level comparison test")
	}
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.img")
	hashPath := filepath.Join(tmpDir, "hash.img")
	dataSize := uint64(1 * 1024 * 1024)

	p := SetupVerityTestParams(dataSize)

	if err := SetupTestData(dataPath, hashPath, p, dataSize); err != nil {
		t.Fatalf("setupTestData failed: %v", err)
	}
	vh := NewVerityHash(p, dataPath, hashPath, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	verityPath := hashPath + ".verity"
	if _, err := GetVeritySetupRootHash(dataPath, hashPath, p); err != nil {
		t.Fatalf("veritysetup format: %v", err)
	}

	// Read veritysetup superblock to get correct offset
	vsF, err := os.Open(verityPath)
	if err != nil {
		t.Fatalf("open vs hash: %v", err)
	}
	defer vsF.Close()

	vsSuperblockData, err := readBlock(vsF, 0, VeritySuperblockSize)
	if err != nil {
		t.Fatalf("read vs superblock: %v", err)
	}
	vsSuperblock, err := DeserializeSuperBlock(vsSuperblockData)
	if err != nil {
		t.Fatalf("deserialize vs superblock: %v", err)
	}

	// Use veritysetup's offset for comparison
	vsHashAreaOffset := alignUp(VeritySuperblockSize, uint64(vsSuperblock.HashBlockSize))

	levels, err := vh.calculateHashLevels()
	if err != nil {
		t.Fatalf("levels: %v", err)
	}
	ourF, err := os.Open(hashPath)
	if err != nil {
		t.Fatalf("open our hash: %v", err)
	}
	defer ourF.Close()

	for lvlIdx, lvl := range levels {
		for blk := uint64(0); blk < lvl.numBlocks; blk++ {
			ourOff := lvl.offset + blk*uint64(p.HashBlockSize)
			vsOff := vsHashAreaOffset + (ourOff - p.HashAreaOffset)

			ours, err := readBlock(ourF, ourOff, p.HashBlockSize)
			if err != nil {
				t.Fatalf("read our lvl %d blk %d: %v", lvlIdx, blk, err)
			}
			theirs, err := readBlock(vsF, vsOff, p.HashBlockSize)
			if err != nil {
				t.Fatalf("read vs lvl %d blk %d: %v", lvlIdx, blk, err)
			}
			if fmt.Sprintf("%x", ours) != fmt.Sprintf("%x", theirs) {
				t.Fatalf("block mismatch at level %d block %d (our offset %d, vs offset %d)", lvlIdx, blk, ourOff, vsOff)
			}
		}
	}
}
