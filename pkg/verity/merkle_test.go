package verity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"regexp"
	"testing"
)

func createTestDataFile(t *testing.T, blockSize uint32, numBlocks uint64) (string, []byte) {
	t.Helper()

	dataFile, err := os.CreateTemp("", "verity-test-data-*")
	if err != nil {
		t.Fatalf("failed to create temp data file: %v", err)
	}

	totalSize := uint64(blockSize) * numBlocks
	data := make([]byte, totalSize)
	if _, err := rand.Read(data); err != nil {
		dataFile.Close()
		os.Remove(dataFile.Name())
		t.Fatalf("failed to generate random data: %v", err)
	}

	if _, err := dataFile.Write(data); err != nil {
		dataFile.Close()
		os.Remove(dataFile.Name())
		t.Fatalf("failed to write test data: %v", err)
	}

	if err := dataFile.Sync(); err != nil {
		dataFile.Close()
		os.Remove(dataFile.Name())
		t.Fatalf("failed to sync data file: %v", err)
	}

	dataFile.Close()
	return dataFile.Name(), data
}

func createTestHashFile(t *testing.T, size int64) string {
	t.Helper()

	hashFile, err := os.CreateTemp("", "verity-test-hash-*")
	if err != nil {
		t.Fatalf("failed to create temp hash file: %v", err)
	}

	if size > 0 {
		if err := hashFile.Truncate(size); err != nil {
			hashFile.Close()
			os.Remove(hashFile.Name())
			t.Fatalf("failed to truncate hash file: %v", err)
		}
	}

	hashFile.Close()
	return hashFile.Name()
}

func extractRootHash(t *testing.T, output string) string {
	t.Helper()
	re := regexp.MustCompile(`(?i)Root hash:\s*([0-9a-f]+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) < 2 {
		t.Fatalf("failed to extract root hash from output: %s", output)
	}
	return matches[1]
}

func TestHashFileContentComparison(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping hash file comparison test")
	}

	tests := []struct {
		name          string
		dataBlockSize uint32
		hashBlockSize uint32
		numBlocks     uint64
		hashType      uint32
		hashAlgo      string
		useSalt       bool
	}{
		{
			name:          "basic test - no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       false,
		},
		{
			name:          "with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     32,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       true,
		},
		{
			name:          "sha512",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha512",
			useSalt:       false,
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
			if tt.useSalt {
				salt = []byte("comparison-test-salt")
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
			}

			vhGo := NewVerityHash(params, dataPath, hashPathGo, nil)
			err := vhGo.createOrVerifyHashTree(false)
			if err != nil {
				t.Fatalf("Go createOrVerifyHashTree failed: %v", err)
			}
			rootHashGo := vhGo.RootHash()

			args := []string{
				"format",
				dataPath,
				hashPathC,
				"--hash", tt.hashAlgo,
				"--data-block-size", "4096",
				"--hash-block-size", "4096",
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
				t.Fatalf("failed to decode cryptsetup root hash: %v", err)
			}

			if !bytes.Equal(rootHashGo, rootHashCBytes) {
				t.Errorf("Root hash mismatch:\nGo:         %x\ncryptsetup: %x",
					rootHashGo, rootHashCBytes)
			}

			superblockSize := int(tt.hashBlockSize)

			hashPathCStripped := createTestHashFile(t, int64(tt.hashBlockSize*uint32(tt.numBlocks)*2))
			defer os.Remove(hashPathCStripped)

			hashContentCFull, err2 := os.ReadFile(hashPathC)
			if err2 != nil {
				t.Fatalf("failed to read cryptsetup hash file: %v", err2)
			}

			if len(hashContentCFull) > superblockSize {
				hashTreeOnly := hashContentCFull[superblockSize:]

				if err3 := os.WriteFile(hashPathCStripped, hashTreeOnly, 0644); err3 != nil {
					t.Fatalf("failed to write stripped hash file: %v", err3)
				}

				vhVerifyStripped := NewVerityHash(params, dataPath, hashPathCStripped, rootHashCBytes)
				err = vhVerifyStripped.createOrVerifyHashTree(true)
				if err != nil {
					t.Errorf("Go verifying stripped cryptsetup hash: ❌ FAILED (%v)", err)
				}
			}

			vhVerifyGo := NewVerityHash(params, dataPath, hashPathGo, rootHashGo)
			err = vhVerifyGo.createOrVerifyHashTree(true)
			if err != nil {
				t.Errorf("Go verifying own hash: ❌ FAILED (%v)", err)
			}
		})
	}
}

func TestCrossCheckWithCryptsetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping cross-check test")
	}

	tests := []struct {
		name          string
		dataBlockSize uint32
		hashBlockSize uint32
		numBlocks     uint64
		hashType      uint32
		hashAlgo      string
		useSalt       bool
	}{
		{
			name:          "basic test - no salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       false,
		},
		{
			name:          "with salt",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     32,
			hashType:      1,
			hashAlgo:      "sha256",
			useSalt:       true,
		},
		{
			name:          "sha512",
			dataBlockSize: 4096,
			hashBlockSize: 4096,
			numBlocks:     16,
			hashType:      1,
			hashAlgo:      "sha512",
			useSalt:       false,
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
			if tt.useSalt {
				salt = []byte("cross-check-salt")
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
			}

			vhGo := NewVerityHash(params, dataPath, hashPathGo, nil)
			err := vhGo.createOrVerifyHashTree(false)
			if err != nil {
				t.Fatalf("Go createOrVerifyHashTree failed: %v", err)
			}
			rootHashGo := vhGo.RootHash()

			args := []string{
				"format",
				dataPath,
				hashPathC,
				"--hash", tt.hashAlgo,
				"--data-block-size", "4096",
				"--hash-block-size", "4096",
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
				t.Fatalf("failed to decode cryptsetup root hash: %v", err)
			}

			if !bytes.Equal(rootHashGo, rootHashCBytes) {
				t.Errorf("Root hash mismatch:\nGo:         %x\ncryptsetup: %x",
					rootHashGo, rootHashCBytes)
			}

			vhSelfVerify := NewVerityHash(params, dataPath, hashPathGo, rootHashGo)
			err = vhSelfVerify.createOrVerifyHashTree(true)
			if err != nil {
				t.Errorf("Go failed to verify its own hash tree: %v", err)
			}
		})
	}
}

func TestManualHashTreeVerification(t *testing.T) {
	dataBlockSize := uint32(4096)
	hashBlockSize := uint32(4096)
	numBlocks := uint64(4)

	dataPath, err := os.CreateTemp("", "manual-verify-data-*")
	if err != nil {
		t.Fatalf("failed to create data file: %v", err)
	}
	defer os.Remove(dataPath.Name())

	for i := uint64(0); i < numBlocks; i++ {
		block := make([]byte, dataBlockSize)
		for j := range block {
			block[j] = byte(i)
		}
		if _, err := dataPath.Write(block); err != nil {
			t.Fatalf("failed to write data: %v", err)
		}
	}
	dataPath.Sync()
	dataPath.Close()

	hashPath := createTestHashFile(t, int64(hashBlockSize*uint32(numBlocks)))
	defer os.Remove(hashPath)

	salt := []byte("manual-test")
	params := &VerityParams{
		HashName:       "sha256",
		DataBlockSize:  dataBlockSize,
		HashBlockSize:  hashBlockSize,
		DataBlocks:     numBlocks,
		HashType:       1,
		Salt:           salt,
		SaltSize:       uint16(len(salt)),
		HashAreaOffset: 0,
	}

	vh := NewVerityHash(params, dataPath.Name(), hashPath, nil)
	err = vh.createOrVerifyHashTree(false)
	if err != nil {
		t.Fatalf("createOrVerifyHashTree failed: %v", err)
	}

	rootHash := vh.RootHash()

	dataFile, err := os.Open(dataPath.Name())
	if err != nil {
		t.Fatalf("failed to open data file: %v", err)
	}
	defer dataFile.Close()

	for i := uint64(0); i < numBlocks; i++ {
		block := make([]byte, dataBlockSize)
		if _, err := dataFile.Read(block); err != nil {
			t.Fatalf("failed to read block %d: %v", i, err)
		}

		_, err := vh.verifyHashBlock(block, salt)
		if err != nil {
			t.Fatalf("failed to calculate hash for block %d: %v", i, err)
		}
	}

	vhVerify := NewVerityHash(params, dataPath.Name(), hashPath, rootHash)
	err = vhVerify.createOrVerifyHashTree(true)
	if err != nil {
		t.Errorf("verification failed: %v", err)
	}
}

func TestHashTreeStructure(t *testing.T) {
	dataBlockSize := uint32(4096)
	hashBlockSize := uint32(4096)
	numBlocks := uint64(256)

	dataPath, _ := createTestDataFile(t, dataBlockSize, numBlocks)
	defer os.Remove(dataPath)

	hashPath := createTestHashFile(t, int64(hashBlockSize*uint32(numBlocks)*2))
	defer os.Remove(hashPath)

	params := &VerityParams{
		HashName:       "sha256",
		DataBlockSize:  dataBlockSize,
		HashBlockSize:  hashBlockSize,
		DataBlocks:     numBlocks,
		HashType:       1,
		Salt:           []byte("structure-test"),
		SaltSize:       14,
		HashAreaOffset: 0,
	}

	vh := NewVerityHash(params, dataPath, hashPath, nil)

	_, err := vh.hashLevels(numBlocks)
	if err != nil {
		t.Fatalf("hashLevels failed: %v", err)
	}

	err = vh.createOrVerifyHashTree(false)
	if err != nil {
		t.Fatalf("createOrVerifyHashTree failed: %v", err)
	}

	rootHash := vh.RootHash()

	vhVerify := NewVerityHash(params, dataPath, hashPath, rootHash)
	err = vhVerify.createOrVerifyHashTree(true)
	if err != nil {
		t.Errorf("verification failed: %v", err)
	}
}
