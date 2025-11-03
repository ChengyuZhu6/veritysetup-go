package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
	verity "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
)

func TestFormatRootHash(t *testing.T) {
	utils.RequireTool(t, "veritysetup")

	data := utils.MakeTempFile(t, 4096*16)
	hashGo := utils.MakeTempFile(t, 0)
	hashC := utils.MakeTempFile(t, 0)

	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--format", "1", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", data, hashGo)
	rootGo := utils.ExtractRootHex(t, outGo)

	cmd := exec.Command("veritysetup", "format", data, hashC, "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-")
	outC, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup format failed: %v\n%s", err, string(outC))
	}
	rootC := utils.ExtractRootHex(t, string(outC))

	if rootGo != rootC {
		t.Fatalf("root hash mismatch: go=%s, c=%s", rootGo, rootC)
	}
}

func TestFormat_WithSuperblock(t *testing.T) {
	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)

	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", data, hash)
	rootGo := utils.ExtractRootHex(t, outGo)

	if rootGo == "" {
		t.Fatal("failed to extract root hash")
	}

	f, err := os.Open(hash)
	if err != nil {
		t.Fatalf("failed to open hash file: %v", err)
	}
	defer f.Close()

	sb, err := verity.ReadSuperblock(f, 0)
	if err != nil {
		t.Fatalf("failed to read superblock: %v", err)
	}

	if sb.Version != 1 {
		t.Errorf("expected version 1, got %d", sb.Version)
	}
	if sb.DataBlockSize != 4096 {
		t.Errorf("expected data block size 4096, got %d", sb.DataBlockSize)
	}
	if sb.HashBlockSize != 4096 {
		t.Errorf("expected hash block size 4096, got %d", sb.HashBlockSize)
	}
}

func TestFormat_NoSuperblock(t *testing.T) {
	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)

	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", "--no-superblock", "--hash-offset", "0", data, hash)
	rootGo := utils.ExtractRootHex(t, outGo)

	if rootGo == "" {
		t.Fatal("failed to extract root hash")
	}

	f, err := os.Open(hash)
	if err != nil {
		t.Fatalf("failed to open hash file: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 512)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatalf("failed to read hash file: %v", err)
	}

	if string(buf[:8]) == verity.VeritySignature {
		t.Error("superblock should not be present with --no-superblock")
	}
}

func TestFormat_WithUUID(t *testing.T) {
	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)

	testUUID := "12345678-1234-1234-1234-123456789abc"
	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", "--uuid", testUUID, data, hash)

	if !strings.Contains(outGo, testUUID) {
		t.Errorf("output should contain UUID %s", testUUID)
	}

	f, err := os.Open(hash)
	if err != nil {
		t.Fatalf("failed to open hash file: %v", err)
	}
	defer f.Close()

	sb, err := verity.ReadSuperblock(f, 0)
	if err != nil {
		t.Fatalf("failed to read superblock: %v", err)
	}

	uuidStr, err := sb.UUIDString()
	if err != nil {
		t.Fatalf("failed to get UUID string: %v", err)
	}

	if uuidStr != testUUID {
		t.Errorf("expected UUID %s, got %s", testUUID, uuidStr)
	}
}

func TestParseFormatArgs_InvalidBlockSize(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "invalid data block size",
			args: []string{"--data-block-size", "1000", "data", "hash"},
		},
		{
			name: "invalid hash block size",
			args: []string{"--hash-block-size", "1000", "data", "hash"},
		},
		{
			name: "missing arguments",
			args: []string{"data"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parseFormatArgs(tt.args)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
