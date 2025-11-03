package main

import (
	"os"
	"os/exec"
	"testing"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
)

func TestVerify(t *testing.T) {
	utils.RequireTool(t, "veritysetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)

	params := utils.DefaultVerityTestParams()
	args := params.BuildVerifyArgs(data, hash, rootHex)
	_, _ = utils.RunGoCLI(t, args...)

	cArgs := params.BuildCVeritysetupVerifyArgs(data, hash, rootHex)
	out, err := exec.Command("veritysetup", cArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup verify failed: %v\n%s", err, string(out))
	}
}

func TestVerify_CrossImplementation(t *testing.T) {
	utils.RequireTool(t, "veritysetup")

	data, hash := utils.MakeTempFile(t, 4096*16), utils.MakeTempFile(t, 0)
	params := utils.DefaultVerityTestParams()

	formatArgs := []string{"format"}
	if params.Hash != "" {
		formatArgs = append(formatArgs, "--hash", params.Hash)
	}
	if params.DataBlockSize != "" {
		formatArgs = append(formatArgs, "--data-block-size", params.DataBlockSize)
	}
	if params.HashBlockSize != "" {
		formatArgs = append(formatArgs, "--hash-block-size", params.HashBlockSize)
	}
	if params.Salt != "" {
		formatArgs = append(formatArgs, "--salt", params.Salt)
	}
	if params.NoSuperblock {
		formatArgs = append(formatArgs, "--no-superblock")
		if params.HashOffset != "" {
			formatArgs = append(formatArgs, "--hash-offset", params.HashOffset)
		}
	}
	formatArgs = append(formatArgs, data, hash)

	outC, err := exec.Command("veritysetup", formatArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup format failed: %v\n%s", err, string(outC))
	}
	rootHex := utils.ExtractRootHex(t, string(outC))

	verifyArgs := params.BuildVerifyArgs(data, hash, rootHex)
	_, _ = utils.RunGoCLI(t, verifyArgs...)
}

func TestVerify_WithSuperblock(t *testing.T) {
	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)

	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", data, hash)
	rootHex := utils.ExtractRootHex(t, outGo)

	_, _ = utils.RunGoCLI(t, "verify", data, hash, rootHex)
}

func TestVerify_NoSuperblock(t *testing.T) {
	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)

	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", "--no-superblock", "--hash-offset", "0", data, hash)
	rootHex := utils.ExtractRootHex(t, outGo)

	params := utils.DefaultVerityTestParams()
	args := params.BuildVerifyArgs(data, hash, rootHex)
	_, _ = utils.RunGoCLI(t, args...)
}

func TestVerify_CorruptedData(t *testing.T) {
	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)

	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", data, hash)
	rootHex := utils.ExtractRootHex(t, outGo)

	f, err := os.OpenFile(data, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("failed to open data file: %v", err)
	}
	if _, err := f.WriteAt([]byte("corrupted"), 0); err != nil {
		t.Fatalf("failed to corrupt data: %v", err)
	}
	f.Close()

	cmd := exec.Command("veritysetup-go", "verify", data, hash, rootHex)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected verification to fail for corrupted data, got output: %s", string(out))
	}
}

func TestVerify_WrongRootHash(t *testing.T) {
	data, hash, _ := utils.CreateFormattedFiles(t)

	wrongRoot := "0000000000000000000000000000000000000000000000000000000000000000"
	cmd := exec.Command("veritysetup-go", "verify", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", data, hash, wrongRoot)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected verification to fail with wrong root hash, got output: %s", string(out))
	}
}

func TestParseVerifyArgs_InvalidArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing arguments",
			args: []string{"data", "hash"},
		},
		{
			name: "invalid data block size",
			args: []string{"--data-block-size", "1000", "data", "hash", "root"},
		},
		{
			name: "invalid hash block size",
			args: []string{"--hash-block-size", "1000", "data", "hash", "root"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := parseVerifyArgs(tt.args)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
