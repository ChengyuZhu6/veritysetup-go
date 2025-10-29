//go:build linux

package main

import (
	"os/exec"
	"testing"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
)

func TestFormat_ParityRootHash(t *testing.T) {
	utils.RequireTool(t, "veritysetup")

	// Prepare data and two separate hash files
	data := utils.MakeTempFile(t, 4096*16)
	hashGo := utils.MakeTempFile(t, 0)
	hashC := utils.MakeTempFile(t, 0)

	// Run veritysetup-go format (explicitly disable salt to match veritysetup invocation)
	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--format", "1", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", data, hashGo)
	rootGo := utils.ExtractRootHex(t, outGo)

	// Run veritysetup format with the same explicit salt disabling
	// Some distros install veritysetup under /sbin not in PATH for tests; rely on LookPath above
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
