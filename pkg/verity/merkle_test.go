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
			params:   setupVerityTestParams(1 * 1024 * 1024),
			wantErr:  false,
		},
		{
			name:     "medium file (10MB)",
			dataSize: 10 * 1024 * 1024,
			params:   setupVerityTestParams(10 * 1024 * 1024),
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
				HashAreaOffset: 4096,
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
				HashAreaOffset: 4096,
			},
			wantErr: false,
		},
		{
			name:     "SHA256 with 2K blocks",
			dataSize: 2 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha256",
				DataBlockSize:  2048,
				HashBlockSize:  2048,
				DataBlocks:     (2 * 1024 * 1024) / 2048,
				HashType:       1,
				Salt:           []byte("test-salt-2k"),
				SaltSize:       uint16(len([]byte("test-salt-2k"))),
				HashAreaOffset: 4096,
			},
			wantErr: false,
		},
		{
			name:     "SHA512 with 8K blocks",
			dataSize: 4 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha512",
				DataBlockSize:  8192,
				HashBlockSize:  8192,
				DataBlocks:     (4 * 1024 * 1024) / 8192,
				HashType:       1,
				Salt:           []byte("test-salt-8k"),
				SaltSize:       uint16(len([]byte("test-salt-8k"))),
				HashAreaOffset: 8192,
			},
			wantErr: false,
		},
		{
			name:     "SHA1 with 4K blocks",
			dataSize: 1 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha1",
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     (1 * 1024 * 1024) / 4096,
				HashType:       1,
				Salt:           []byte("test-salt-sha1"),
				SaltSize:       uint16(len([]byte("test-salt-sha1"))),
				HashAreaOffset: 4096,
			},
			wantErr: false,
		},
		{
			name:     "SHA256 with mixed block sizes (data 4K, hash 8K)",
			dataSize: 2 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha256",
				DataBlockSize:  4096,
				HashBlockSize:  8192,
				DataBlocks:     (2 * 1024 * 1024) / 4096,
				HashType:       1,
				Salt:           []byte("test-mixed"),
				SaltSize:       uint16(len([]byte("test-mixed"))),
				HashAreaOffset: 8192,
			},
			wantErr: false,
		},
		{
			name:     "SHA512 with 1K blocks",
			dataSize: 512 * 1024,
			params: &VerityParams{
				HashName:       "sha512",
				DataBlockSize:  1024,
				HashBlockSize:  1024,
				DataBlocks:     (512 * 1024) / 1024,
				HashType:       1,
				Salt:           []byte("test-sha512-1k"),
				SaltSize:       uint16(len([]byte("test-sha512-1k"))),
				HashAreaOffset: 4096,
			},
			wantErr: false,
		},
		{
			name:     "SHA256 with large file (50MB)",
			dataSize: 50 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha256",
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     (50 * 1024 * 1024) / 4096,
				HashType:       1,
				Salt:           []byte("test-large"),
				SaltSize:       uint16(len([]byte("test-large"))),
				HashAreaOffset: 4096,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			if err := setupTestData(dataPath, hashPath, tt.params, tt.dataSize); err != nil {
				t.Fatalf("setupTestData failed: %v", err)
			}

			if err := testCreateAndVerify(t, tt.params, dataPath, hashPath); (err != nil) != tt.wantErr {
				t.Errorf("testCreateAndVerify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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
			params:   setupVerityTestParams(1024 * 1024),
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
				HashAreaOffset: 4096,
			},
		},
		{
			name:     "2MB file with SHA256 and 2K blocks",
			dataSize: 2 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha256",
				DataBlockSize:  2048,
				HashBlockSize:  2048,
				DataBlocks:     (2 * 1024 * 1024) / 2048,
				HashType:       1,
				Salt:           []byte("test-2k"),
				SaltSize:       uint16(len([]byte("test-2k"))),
				HashAreaOffset: 4096,
			},
		},
		{
			name:     "4MB file with SHA512 and 8K blocks",
			dataSize: 4 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha512",
				DataBlockSize:  8192,
				HashBlockSize:  8192,
				DataBlocks:     (4 * 1024 * 1024) / 8192,
				HashType:       1,
				Salt:           []byte("test-8k"),
				SaltSize:       uint16(len([]byte("test-8k"))),
				HashAreaOffset: 8192,
			},
		},
		{
			name:     "512KB file with SHA256 and 1K blocks",
			dataSize: 512 * 1024,
			params: &VerityParams{
				HashName:       "sha256",
				DataBlockSize:  1024,
				HashBlockSize:  1024,
				DataBlocks:     (512 * 1024) / 1024,
				HashType:       1,
				Salt:           []byte("test-1k"),
				SaltSize:       uint16(len([]byte("test-1k"))),
				HashAreaOffset: 4096,
			},
		},
		{
			name:     "10MB file with SHA256",
			dataSize: 10 * 1024 * 1024,
			params: &VerityParams{
				HashName:       "sha256",
				DataBlockSize:  4096,
				HashBlockSize:  4096,
				DataBlocks:     (10 * 1024 * 1024) / 4096,
				HashType:       1,
				Salt:           []byte("test-10mb"),
				SaltSize:       uint16(len([]byte("test-10mb"))),
				HashAreaOffset: 4096,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			if err := setupTestData(dataPath, hashPath, tt.params, tt.dataSize); err != nil {
				t.Fatalf("setupTestData failed: %v", err)
			}

			vh := NewVerityHash(tt.params, dataPath, hashPath, nil)
			if err := vh.Create(); err != nil {
				t.Fatalf("our implementation create failed: %v", err)
			}
			veritysetupHashPath := hashPath + ".verity"
			if _, err := getVeritySetupRootHash(dataPath, hashPath, tt.params); err != nil {
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
			ourSuperblock := ourHashContent[:VeritySuperblockSize]
			vsSuperblock := vsHashContent[:VeritySuperblockSize]
			if fmt.Sprintf("%x", ourSuperblock) != fmt.Sprintf("%x", vsSuperblock) {
				t.Errorf("superblock mismatch")
			}

			ourHashData := ourHashContent[tt.params.HashAreaOffset:]
			vsHashData := vsHashContent[tt.params.HashAreaOffset:]
			if fmt.Sprintf("%x", ourHashData) != fmt.Sprintf("%x", vsHashData) {
				t.Errorf("hash file content mismatch from offset %d", tt.params.HashAreaOffset)
			}
		})
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

	p := setupVerityTestParams(dataSize)

	if err := setupTestData(dataPath, hashPath, p, dataSize); err != nil {
		t.Fatalf("setupTestData failed: %v", err)
	}
	vh := NewVerityHash(p, dataPath, hashPath, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	verityPath := hashPath + ".verity"
	if _, err := getVeritySetupRootHash(dataPath, hashPath, p); err != nil {
		t.Fatalf("veritysetup format: %v", err)
	}

	vsF, err := os.Open(verityPath)
	if err != nil {
		t.Fatalf("open vs hash: %v", err)
	}
	defer vsF.Close()

	vsSuperblockData, err := readBlock(vsF, 0, VeritySuperblockSize)
	if err != nil {
		t.Fatalf("read vs superblock: %v", err)
	}
	vsSuperblock, err := DeserializeSuperblock(vsSuperblockData)
	if err != nil {
		t.Fatalf("deserialize vs superblock: %v", err)
	}

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

func TestHashAlgorithmCombinations(t *testing.T) {
	hashAlgorithms := []string{"sha1", "sha256", "sha512"}
	blockSizes := []uint32{1024, 2048, 4096, 8192}
	dataSize := uint64(1 * 1024 * 1024)

	for _, hashAlgo := range hashAlgorithms {
		for _, blockSize := range blockSizes {
			testName := fmt.Sprintf("%s_with_%d_blocks", hashAlgo, blockSize)
			t.Run(testName, func(t *testing.T) {
				tmpDir := t.TempDir()
				dataPath := filepath.Join(tmpDir, "data.img")
				hashPath := filepath.Join(tmpDir, "hash.img")

				params := &VerityParams{
					HashName:       hashAlgo,
					DataBlockSize:  blockSize,
					HashBlockSize:  blockSize,
					DataBlocks:     dataSize / uint64(blockSize),
					HashType:       1,
					Salt:           []byte(fmt.Sprintf("salt-%s-%d", hashAlgo, blockSize)),
					SaltSize:       uint16(len([]byte(fmt.Sprintf("salt-%s-%d", hashAlgo, blockSize)))),
					HashAreaOffset: uint64(blockSize),
				}

				if err := setupTestData(dataPath, hashPath, params, dataSize); err != nil {
					t.Fatalf("setupTestData failed: %v", err)
				}

				if err := testCreateAndVerify(t, params, dataPath, hashPath); err != nil {
					t.Errorf("testCreateAndVerify() error = %v", err)
				}
			})
		}
	}
}

func TestDifferentDataSizes(t *testing.T) {
	dataSizes := []struct {
		name string
		size uint64
	}{
		{"128KB", 128 * 1024},
		{"256KB", 256 * 1024},
		{"512KB", 512 * 1024},
		{"1MB", 1 * 1024 * 1024},
		{"2MB", 2 * 1024 * 1024},
		{"5MB", 5 * 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
		{"20MB", 20 * 1024 * 1024},
	}

	for _, ds := range dataSizes {
		t.Run(ds.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			params := setupVerityTestParams(ds.size)

			if err := setupTestData(dataPath, hashPath, params, ds.size); err != nil {
				t.Fatalf("setupTestData failed: %v", err)
			}

			if err := testCreateAndVerify(t, params, dataPath, hashPath); err != nil {
				t.Errorf("testCreateAndVerify() error = %v", err)
			}
		})
	}
}

func TestMixedBlockSizes(t *testing.T) {
	tests := []struct {
		name          string
		dataSize      uint64
		dataBlockSize uint32
		hashBlockSize uint32
		hashAlgo      string
	}{
		{
			name:          "SHA256 data 1K hash 2K",
			dataSize:      1 * 1024 * 1024,
			dataBlockSize: 1024,
			hashBlockSize: 2048,
			hashAlgo:      "sha256",
		},
		{
			name:          "SHA256 data 2K hash 4K",
			dataSize:      2 * 1024 * 1024,
			dataBlockSize: 2048,
			hashBlockSize: 4096,
			hashAlgo:      "sha256",
		},
		{
			name:          "SHA512 data 4K hash 8K",
			dataSize:      4 * 1024 * 1024,
			dataBlockSize: 4096,
			hashBlockSize: 8192,
			hashAlgo:      "sha512",
		},
		{
			name:          "SHA256 data 1K hash 4K",
			dataSize:      1 * 1024 * 1024,
			dataBlockSize: 1024,
			hashBlockSize: 4096,
			hashAlgo:      "sha256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			params := &VerityParams{
				HashName:       tt.hashAlgo,
				DataBlockSize:  tt.dataBlockSize,
				HashBlockSize:  tt.hashBlockSize,
				DataBlocks:     tt.dataSize / uint64(tt.dataBlockSize),
				HashType:       1,
				Salt:           []byte(fmt.Sprintf("salt-%s", tt.name)),
				SaltSize:       uint16(len([]byte(fmt.Sprintf("salt-%s", tt.name)))),
				HashAreaOffset: uint64(tt.hashBlockSize),
			}

			if err := setupTestData(dataPath, hashPath, params, tt.dataSize); err != nil {
				t.Fatalf("setupTestData failed: %v", err)
			}

			if err := testCreateAndVerify(t, params, dataPath, hashPath); err != nil {
				t.Errorf("testCreateAndVerify() error = %v", err)
			}
		})
	}
}

func TestErrorPaths(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("NonExistentDataFile", func(t *testing.T) {
		params := setupVerityTestParams(1024 * 1024)
		vh := NewVerityHash(params, "/nonexistent/data.img", filepath.Join(tmpDir, "hash.img"), nil)
		err := vh.Create()
		if err == nil {
			t.Error("Expected error for non-existent data file, got nil")
		}
	})

	t.Run("NonExistentHashFile", func(t *testing.T) {
		dataPath := filepath.Join(tmpDir, "data.img")
		if err := generateRandomFile(dataPath, 1024*1024); err != nil {
			t.Fatalf("Failed to create data file: %v", err)
		}
		params := setupVerityTestParams(1024 * 1024)
		vh := NewVerityHash(params, dataPath, "/nonexistent/dir/hash.img", nil)
		err := vh.Create()
		if err == nil {
			t.Error("Expected error for non-existent hash file directory, got nil")
		}
	})

	t.Run("InvalidRootHashVerification", func(t *testing.T) {
		dataPath := filepath.Join(tmpDir, "data2.img")
		hashPath := filepath.Join(tmpDir, "hash2.img")
		params := setupVerityTestParams(1024 * 1024)

		if err := setupTestData(dataPath, hashPath, params, 1024*1024); err != nil {
			t.Fatalf("setupTestData failed: %v", err)
		}

		vh := NewVerityHash(params, dataPath, hashPath, nil)
		if err := vh.Create(); err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		wrongRootHash := make([]byte, len(vh.rootHash))
		for i := range wrongRootHash {
			wrongRootHash[i] = ^vh.rootHash[i]
		}

		vh2 := NewVerityHash(params, dataPath, hashPath, wrongRootHash)
		err := vh2.Verify()
		if err == nil {
			t.Error("Expected error for wrong root hash, got nil")
		}
	})
}

func TestBoundaryConditions(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("VerySmallFile", func(t *testing.T) {
		dataPath := filepath.Join(tmpDir, "small.img")
		hashPath := filepath.Join(tmpDir, "small_hash.img")
		dataSize := uint64(512) // Exactly one block

		params := &VerityParams{
			HashName:       "sha256",
			DataBlockSize:  512,
			HashBlockSize:  512,
			DataBlocks:     1,
			HashType:       1,
			Salt:           []byte("small"),
			SaltSize:       5,
			HashAreaOffset: 512,
		}

		if err := setupTestData(dataPath, hashPath, params, dataSize); err != nil {
			t.Fatalf("setupTestData failed: %v", err)
		}

		if err := testCreateAndVerify(t, params, dataPath, hashPath); err != nil {
			t.Errorf("testCreateAndVerify() error = %v", err)
		}
	})

	t.Run("EmptySalt", func(t *testing.T) {
		dataPath := filepath.Join(tmpDir, "nosalt.img")
		hashPath := filepath.Join(tmpDir, "nosalt_hash.img")
		dataSize := uint64(1024 * 1024)

		params := &VerityParams{
			HashName:       "sha256",
			DataBlockSize:  4096,
			HashBlockSize:  4096,
			DataBlocks:     dataSize / 4096,
			HashType:       1,
			Salt:           []byte{},
			SaltSize:       0,
			HashAreaOffset: 4096,
		}

		if err := setupTestData(dataPath, hashPath, params, dataSize); err != nil {
			t.Fatalf("setupTestData failed: %v", err)
		}

		if err := testCreateAndVerify(t, params, dataPath, hashPath); err != nil {
			t.Errorf("testCreateAndVerify() error = %v", err)
		}
	})

	t.Run("MaxSaltSize", func(t *testing.T) {
		dataPath := filepath.Join(tmpDir, "maxsalt.img")
		hashPath := filepath.Join(tmpDir, "maxsalt_hash.img")
		dataSize := uint64(1024 * 1024)

		maxSalt := make([]byte, 256)
		for i := range maxSalt {
			maxSalt[i] = byte(i)
		}

		params := &VerityParams{
			HashName:       "sha256",
			DataBlockSize:  4096,
			HashBlockSize:  4096,
			DataBlocks:     dataSize / 4096,
			HashType:       1,
			Salt:           maxSalt,
			SaltSize:       256,
			HashAreaOffset: 4096,
		}

		if err := setupTestData(dataPath, hashPath, params, dataSize); err != nil {
			t.Fatalf("setupTestData failed: %v", err)
		}

		if err := testCreateAndVerify(t, params, dataPath, hashPath); err != nil {
			t.Errorf("testCreateAndVerify() error = %v", err)
		}
	})

	t.Run("HashType0", func(t *testing.T) {
		dataPath := filepath.Join(tmpDir, "hashtype0.img")
		hashPath := filepath.Join(tmpDir, "hashtype0_hash.img")
		dataSize := uint64(1024 * 1024)

		params := &VerityParams{
			HashName:       "sha256",
			DataBlockSize:  4096,
			HashBlockSize:  4096,
			DataBlocks:     dataSize / 4096,
			HashType:       0,
			Salt:           []byte("test-hashtype0"),
			SaltSize:       14,
			HashAreaOffset: 4096,
		}

		if err := setupTestData(dataPath, hashPath, params, dataSize); err != nil {
			t.Fatalf("setupTestData failed: %v", err)
		}

		if err := testCreateAndVerify(t, params, dataPath, hashPath); err != nil {
			t.Errorf("testCreateAndVerify() error = %v", err)
		}
	})

	t.Run("SingleBlock", func(t *testing.T) {
		dataPath := filepath.Join(tmpDir, "single.img")
		hashPath := filepath.Join(tmpDir, "single_hash.img")
		dataSize := uint64(4096)

		params := &VerityParams{
			HashName:       "sha256",
			DataBlockSize:  4096,
			HashBlockSize:  4096,
			DataBlocks:     1,
			HashType:       1,
			Salt:           []byte("single"),
			SaltSize:       6,
			HashAreaOffset: 4096,
		}

		if err := setupTestData(dataPath, hashPath, params, dataSize); err != nil {
			t.Fatalf("setupTestData failed: %v", err)
		}

		if err := testCreateAndVerify(t, params, dataPath, hashPath); err != nil {
			t.Errorf("testCreateAndVerify() error = %v", err)
		}
	})
}

func TestPublicAPIs(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("RootHashMethod", func(t *testing.T) {
		dataPath := filepath.Join(tmpDir, "api_data.img")
		hashPath := filepath.Join(tmpDir, "api_hash.img")
		dataSize := uint64(1024 * 1024)
		params := setupVerityTestParams(dataSize)

		if err := setupTestData(dataPath, hashPath, params, dataSize); err != nil {
			t.Fatalf("setupTestData failed: %v", err)
		}

		vh := NewVerityHash(params, dataPath, hashPath, nil)
		if err := vh.Create(); err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		rootHash := vh.RootHash()
		if len(rootHash) == 0 {
			t.Error("RootHash() returned empty slice")
		}

		rootHash[0] = ^rootHash[0]
		rootHash2 := vh.RootHash()
		if rootHash[0] == rootHash2[0] {
			t.Error("RootHash() should return a copy, not the original slice")
		}
	})

	t.Run("IsBlockSizeValid", func(t *testing.T) {
		validSizes := []uint32{512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}
		for _, size := range validSizes {
			if !IsBlockSizeValid(size) {
				t.Errorf("Expected %d to be valid block size", size)
			}
		}

		invalidSizes := []uint32{0, 256, 511, 513, 1000, 3000, 5000, 10000, 1024 * 1024}
		for _, size := range invalidSizes {
			if IsBlockSizeValid(size) {
				t.Errorf("Expected %d to be invalid block size", size)
			}
		}
	})

	t.Run("DefaultVerityParams", func(t *testing.T) {
		params := DefaultVerityParams()
		if params.HashName != "sha256" {
			t.Errorf("Expected default hash name 'sha256', got '%s'", params.HashName)
		}
		if params.DataBlockSize != 4096 {
			t.Errorf("Expected default data block size 4096, got %d", params.DataBlockSize)
		}
		if params.HashBlockSize != 4096 {
			t.Errorf("Expected default hash block size 4096, got %d", params.HashBlockSize)
		}
		if params.HashType != 1 {
			t.Errorf("Expected default hash type 1, got %d", params.HashType)
		}
	})
}

func TestUnsupportedHashAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.img")
	hashPath := filepath.Join(tmpDir, "hash.img")
	dataSize := uint64(1024 * 1024)

	params := &VerityParams{
		HashName:       "invalid-hash-algo",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataBlocks:     dataSize / 4096,
		HashType:       1,
		Salt:           []byte("test"),
		SaltSize:       4,
		HashAreaOffset: 4096,
	}

	if err := setupTestData(dataPath, hashPath, params, dataSize); err != nil {
		t.Fatalf("setupTestData failed: %v", err)
	}

	vh := NewVerityHash(params, dataPath, hashPath, nil)
	if err := vh.Create(); err != nil {
		t.Errorf("Create failed even with fallback: %v", err)
	}

	if err := vh.Verify(); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}
