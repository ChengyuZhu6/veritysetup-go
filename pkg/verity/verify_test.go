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

	v, err := NewVerifier(p, data, hash, vh.rootHash, VerifyAlways)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	if err := v.VerifyAll(); err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
}

func TestVerifierRangeAndBlock(t *testing.T) {
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data.img")
	hash := filepath.Join(tmp, "hash.img")
	size := uint64(2 * 1024 * 1024)
	p := setupVerityTestParams(size)
	if err := setupTestData(data, hash, p, size); err != nil {
		t.Fatalf("setup: %v", err)
	}

	vh := NewVerityHash(p, data, hash, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	v, err := NewVerifier(p, data, hash, vh.rootHash, VerifyAtMostOnce)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	if err := v.VerifyRange(0, size/2); err != nil {
		t.Fatalf("VerifyRange: %v", err)
	}
	lastBlock := p.DataBlocks - 1
	if err := v.VerifyBlock(lastBlock); err != nil {
		t.Fatalf("VerifyBlock: %v", err)
	}
	if err := v.VerifyBlock(lastBlock); err != nil {
		t.Fatalf("VerifyBlock repeat: %v", err)
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

	v, err := NewVerifier(p, data, hash, vh.rootHash, VerifyAlways)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	if err := v.VerifyBlock(0); err == nil {
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

	v, err := NewVerifier(p, data, verityHashPath, root, VerifyAlways)
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
	if err := v.VerifyBlock(0); err == nil {
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
	p.HashAreaOffset = 0 // No offset for no-superblock mode

	if err := setupTestData(data, hash, p, size); err != nil {
		t.Fatalf("setup: %v", err)
	}

	vh := NewVerityHash(p, data, hash, nil)
	if err := vh.Create(); err != nil {
		t.Fatalf("create: %v", err)
	}

	v, err := NewVerifier(p, data, hash, vh.rootHash, VerifyAlways)
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

	v2, err := NewVerifier(p, data, hash, vh.rootHash, VerifyAlways)
	if err != nil {
		t.Fatalf("NewVerifier after corruption: %v", err)
	}
	defer v2.Close()

	if err := v2.VerifyBlock(0); err == nil {
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

	// Verify veritysetup's hash file with our verifier
	verityHashPath := hash + ".verity"
	v, err := NewVerifier(p, data, verityHashPath, vsRoot, VerifyAlways)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	if err := v.VerifyAll(); err != nil {
		t.Fatalf("VerifyAll vs veritysetup: %v", err)
	}

	// Test corruption detection with both tools
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

	if err := v.VerifyBlock(0); err == nil {
		t.Fatalf("expected corruption with veritysetup hash, got nil")
	}
}
