package verity

import (
	"encoding/hex"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVerifierVerifyAll(t *testing.T) {
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data.img")
	hash := filepath.Join(tmp, "hash.img")

	size := uint64(1 * 1024 * 1024)
	p := setupVerityTestParams(size)
	if err := setupTestData(data, hash, p, size); err != nil {
		t.Fatalf("setup: %v", err)
	}

	vh := NewVerityHash(p, data, hash, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	v, err := NewVerifier(p, data, hash, vh.rootHash)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	if err := v.VerifyAll(); err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
}

func TestVerifierDetectsCorruption(t *testing.T) {
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data.img")
	hash := filepath.Join(tmp, "hash.img")
	size := uint64(1 * 1024 * 1024)
	p := setupVerityTestParams(size)
	if err := setupTestData(data, hash, p, size); err != nil {
		t.Fatalf("setup: %v", err)
	}

	vh := NewVerityHash(p, data, hash, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := corruptFile(data, 0); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	v, err := NewVerifier(p, data, hash, vh.rootHash)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	if err := v.VerifyAll(); err == nil {
		t.Fatalf("expected corruption error, got nil")
	}
}

func TestVerifierAgainstVeritySetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping comparison test")
	}

	tmp := t.TempDir()
	data := filepath.Join(tmp, "data.img")
	hash := filepath.Join(tmp, "hash.img")
	size := uint64(1 * 1024 * 1024)

	if err := generateRandomFile(data, size); err != nil {
		t.Fatalf("generate data: %v", err)
	}
	p := setupVerityTestParams(size)

	root, err := getVeritySetupRootHash(data, hash, p)
	if err != nil {
		t.Fatalf("veritysetup format: %v", err)
	}
	verityHashPath := hash + ".verity"

	verifyCmd := exec.Command(
		"veritysetup", "verify",
		"--hash", p.HashName,
		"--data-block-size", "4096",
		"--hash-block-size", "4096",
		"--salt", hex.EncodeToString(p.Salt),
		data, verityHashPath, hex.EncodeToString(root),
	)
	if out, err := verifyCmd.CombinedOutput(); err != nil {
		t.Fatalf("veritysetup verify failed: %v\nOutput: %s", err, out)
	}

	v, err := NewVerifier(p, data, verityHashPath, root)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	if err := v.VerifyAll(); err != nil {
		t.Fatalf("VerifyAll vs veritysetup: %v", err)
	}

	if err := corruptFile(data, 0); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	verifyCmdBad := exec.Command(
		"veritysetup", "verify",
		"--hash", p.HashName,
		"--data-block-size", "4096",
		"--hash-block-size", "4096",
		"--salt", hex.EncodeToString(p.Salt),
		data, verityHashPath, hex.EncodeToString(root),
	)
	if out, err := verifyCmdBad.CombinedOutput(); err == nil {
		t.Fatalf("expected veritysetup verify to fail after corruption, got success. Output: %s", out)
	}
	if err := v.VerifyAll(); err == nil {
		t.Fatalf("expected corruption with veritysetup hash, got nil")
	}
}

func TestVerifierNoSuperblock(t *testing.T) {
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data.img")
	hash := filepath.Join(tmp, "hash.img")
	size := uint64(1 * 1024 * 1024)

	p := setupVerityTestParams(size)
	p.NoSuperblock = true
	p.HashAreaOffset = 0

	if err := setupTestData(data, hash, p, size); err != nil {
		t.Fatalf("setup: %v", err)
	}

	vh := NewVerityHash(p, data, hash, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	v, err := NewVerifier(p, data, hash, vh.rootHash)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	if err := v.VerifyAll(); err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}

	if err := corruptFile(data, 0); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	v2, err := NewVerifier(p, data, hash, vh.rootHash)
	if err != nil {
		t.Fatalf("NewVerifier after corruption: %v", err)
	}
	defer v2.Close()

	if err := v2.VerifyAll(); err == nil {
		t.Fatalf("expected corruption error, got nil")
	}
}

func TestVerifierNoSuperblockAgainstVeritySetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found, skipping comparison test")
	}

	tmp := t.TempDir()
	data := filepath.Join(tmp, "data.img")
	hash := filepath.Join(tmp, "hash.img")
	size := uint64(1 * 1024 * 1024)

	if err := generateRandomFile(data, size); err != nil {
		t.Fatalf("generate data: %v", err)
	}

	p := setupVerityTestParams(size)
	p.NoSuperblock = true
	p.HashAreaOffset = 0

	if err := setupTestData(data, hash, p, size); err != nil {
		t.Fatalf("setup: %v", err)
	}

	vh := NewVerityHash(p, data, hash, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	vsRoot, err := getVeritySetupRootHash(data, hash, p)
	if err != nil {
		t.Fatalf("veritysetup format: %v", err)
	}

	if hex.EncodeToString(vh.rootHash) != hex.EncodeToString(vsRoot) {
		t.Fatalf("root hash mismatch:\nours:       %x\nveritysetup: %x", vh.rootHash, vsRoot)
	}

	verifyCmd := exec.Command(
		"veritysetup", "verify",
		"--hash", p.HashName,
		"--no-superblock",
		"--data-block-size", "4096",
		"--hash-block-size", "4096",
		"--salt", hex.EncodeToString(p.Salt),
		data, hash, hex.EncodeToString(vh.rootHash),
	)
	if out, err := verifyCmd.CombinedOutput(); err != nil {
		t.Fatalf("veritysetup verify failed on our hash file: %v\nOutput: %s", err, out)
	}

	verityHashPath := hash + ".verity"
	v, err := NewVerifier(p, data, verityHashPath, vsRoot)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	if err := v.VerifyAll(); err != nil {
		t.Fatalf("VerifyAll vs veritysetup: %v", err)
	}

	if err := corruptFile(data, 0); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	verifyCmdBad := exec.Command(
		"veritysetup", "verify",
		"--hash", p.HashName,
		"--no-superblock",
		"--data-block-size", "4096",
		"--hash-block-size", "4096",
		"--salt", hex.EncodeToString(p.Salt),
		data, hash, hex.EncodeToString(vh.rootHash),
	)
	if out, err := verifyCmdBad.CombinedOutput(); err == nil {
		t.Fatalf("expected veritysetup verify to fail after corruption, got success. Output: %s", out)
	}

	if err := v.VerifyAll(); err == nil {
		t.Fatalf("expected corruption with veritysetup hash, got nil")
	}
}

func TestVerifierErrorPaths(t *testing.T) {
	tmp := t.TempDir()

	t.Run("NonExistentDataFile", func(t *testing.T) {
		hash := filepath.Join(tmp, "hash.img")
		p := setupVerityTestParams(1024 * 1024)
		rootHash := make([]byte, 32)

		if err := generateRandomFile(hash, 4096); err != nil {
			t.Fatalf("Failed to create hash file: %v", err)
		}

		_, err := NewVerifier(p, "/nonexistent/data.img", hash, rootHash)
		if err == nil {
			t.Error("Expected error for non-existent data file, got nil")
		}
	})

	t.Run("NonExistentHashFile", func(t *testing.T) {
		data := filepath.Join(tmp, "data2.img")
		p := setupVerityTestParams(1024 * 1024)
		rootHash := make([]byte, 32)

		if err := generateRandomFile(data, 1024*1024); err != nil {
			t.Fatalf("Failed to create data file: %v", err)
		}

		_, err := NewVerifier(p, data, "/nonexistent/hash.img", rootHash)
		if err == nil {
			t.Error("Expected error for non-existent hash file, got nil")
		}
	})

	t.Run("NilRootHash", func(t *testing.T) {
		data := filepath.Join(tmp, "data3.img")
		hash := filepath.Join(tmp, "hash3.img")
		p := setupVerityTestParams(1024 * 1024)

		if err := generateRandomFile(data, 1024*1024); err != nil {
			t.Fatalf("Failed to create data file: %v", err)
		}
		if err := generateRandomFile(hash, 4096); err != nil {
			t.Fatalf("Failed to create hash file: %v", err)
		}

		v, err := NewVerifier(p, data, hash, nil)
		if err != nil {
			t.Fatalf("NewVerifier failed: %v", err)
		}
		defer v.Close()

		if err := v.VerifyAll(); err == nil {
			t.Error("Expected error when verifying with nil root hash, got nil")
		}
	})

	t.Run("EmptyRootHash", func(t *testing.T) {
		data := filepath.Join(tmp, "data4.img")
		hash := filepath.Join(tmp, "hash4.img")
		p := setupVerityTestParams(1024 * 1024)

		if err := generateRandomFile(data, 1024*1024); err != nil {
			t.Fatalf("Failed to create data file: %v", err)
		}
		if err := generateRandomFile(hash, 4096); err != nil {
			t.Fatalf("Failed to create hash file: %v", err)
		}

		v, err := NewVerifier(p, data, hash, []byte{})
		if err != nil {
			t.Fatalf("NewVerifier failed: %v", err)
		}
		defer v.Close()

		if err := v.VerifyAll(); err == nil {
			t.Error("Expected error when verifying with empty root hash, got nil")
		}
	})

	t.Run("CorruptedHashTree", func(t *testing.T) {
		data := filepath.Join(tmp, "data5.img")
		hash := filepath.Join(tmp, "hash5.img")
		size := uint64(1 * 1024 * 1024)
		p := setupVerityTestParams(size)

		if err := setupTestData(data, hash, p, size); err != nil {
			t.Fatalf("setup: %v", err)
		}

		vh := NewVerityHash(p, data, hash, nil)
		if err := vh.Create(); err != nil {
			t.Fatalf("create: %v", err)
		}

		// Corrupt the hash file
		if err := corruptFile(hash, int64(p.HashAreaOffset)); err != nil {
			t.Fatalf("corrupt hash: %v", err)
		}

		v, err := NewVerifier(p, data, hash, vh.rootHash)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		defer v.Close()

		if err := v.VerifyAll(); err == nil {
			t.Error("Expected error for corrupted hash tree, got nil")
		}
	})
}

func TestVerifierBoundaryConditions(t *testing.T) {
	tmp := t.TempDir()

	t.Run("SingleBlockFile", func(t *testing.T) {
		data := filepath.Join(tmp, "single.img")
		hash := filepath.Join(tmp, "single_hash.img")
		size := uint64(4096)
		p := setupVerityTestParams(size)

		if err := setupTestData(data, hash, p, size); err != nil {
			t.Fatalf("setup: %v", err)
		}

		vh := NewVerityHash(p, data, hash, nil)
		if err := vh.Create(); err != nil {
			t.Fatalf("create: %v", err)
		}

		v, err := NewVerifier(p, data, hash, vh.rootHash)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		defer v.Close()

		if err := v.VerifyAll(); err != nil {
			t.Errorf("VerifyAll failed: %v", err)
		}
	})

	t.Run("VerySmallFile", func(t *testing.T) {
		data := filepath.Join(tmp, "tiny.img")
		hash := filepath.Join(tmp, "tiny_hash.img")
		size := uint64(512)

		p := &VerityParams{
			HashName:       "sha256",
			DataBlockSize:  512,
			HashBlockSize:  512,
			DataBlocks:     1,
			HashType:       1,
			Salt:           []byte("tiny"),
			SaltSize:       4,
			HashAreaOffset: 512,
		}

		if err := setupTestData(data, hash, p, size); err != nil {
			t.Fatalf("setup: %v", err)
		}

		vh := NewVerityHash(p, data, hash, nil)
		if err := vh.Create(); err != nil {
			t.Fatalf("create: %v", err)
		}

		v, err := NewVerifier(p, data, hash, vh.rootHash)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		defer v.Close()

		if err := v.VerifyAll(); err != nil {
			t.Errorf("VerifyAll failed: %v", err)
		}
	})

	t.Run("MultipleCorruptedBlocks", func(t *testing.T) {
		data := filepath.Join(tmp, "multi_corrupt.img")
		hash := filepath.Join(tmp, "multi_corrupt_hash.img")
		size := uint64(10 * 1024 * 1024)
		p := setupVerityTestParams(size)

		if err := setupTestData(data, hash, p, size); err != nil {
			t.Fatalf("setup: %v", err)
		}

		vh := NewVerityHash(p, data, hash, nil)
		if err := vh.Create(); err != nil {
			t.Fatalf("create: %v", err)
		}

		offsets := []int64{0, 100 * 4096, 500 * 4096, 1000 * 4096}
		for _, offset := range offsets {
			if err := corruptFile(data, offset); err != nil {
				t.Fatalf("corrupt at %d: %v", offset, err)
			}
		}

		v, err := NewVerifier(p, data, hash, vh.rootHash)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		defer v.Close()

		if err := v.VerifyAll(); err == nil {
			t.Error("Expected error for multiple corrupted blocks, got nil")
		}
	})

	t.Run("LastBlockCorruption", func(t *testing.T) {
		data := filepath.Join(tmp, "last_corrupt.img")
		hash := filepath.Join(tmp, "last_corrupt_hash.img")
		size := uint64(1 * 1024 * 1024)
		p := setupVerityTestParams(size)

		if err := setupTestData(data, hash, p, size); err != nil {
			t.Fatalf("setup: %v", err)
		}

		vh := NewVerityHash(p, data, hash, nil)
		if err := vh.Create(); err != nil {
			t.Fatalf("create: %v", err)
		}

		// Corrupt the last block
		lastBlockOffset := int64(size - uint64(p.DataBlockSize))
		if err := corruptFile(data, lastBlockOffset); err != nil {
			t.Fatalf("corrupt last block: %v", err)
		}

		v, err := NewVerifier(p, data, hash, vh.rootHash)
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		defer v.Close()

		if err := v.VerifyAll(); err == nil {
			t.Error("Expected error for last block corruption, got nil")
		}
	})
}

func TestVerifierClose(t *testing.T) {
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data.img")
	hash := filepath.Join(tmp, "hash.img")
	size := uint64(1 * 1024 * 1024)
	p := setupVerityTestParams(size)

	if err := setupTestData(data, hash, p, size); err != nil {
		t.Fatalf("setup: %v", err)
	}

	vh := NewVerityHash(p, data, hash, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	v, err := NewVerifier(p, data, hash, vh.rootHash)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if err := v.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	err = v.Close()
	if err == nil {
		t.Log("Second Close() succeeded (files may be nil)")
	} else {
		t.Logf("Second Close() failed as expected: %v", err)
	}
}
