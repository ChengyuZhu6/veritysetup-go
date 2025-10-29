//go:build linux

package main

import (
	"os/exec"
	"testing"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
)

func TestVerify_Parity(t *testing.T) {
	utils.RequireTool(t, "veritysetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)

	// veritysetup-go verify
	_, _ = utils.RunGoCLI(t, "verify", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", data, hash, rootHex)

	// veritysetup verify
	cmd := exec.Command(
		"veritysetup", "--debug", "--verbose", "verify",
		data, hash, rootHex,
		"--hash", "sha256",
		"--data-block-size", "4096",
		"--hash-block-size", "4096",
		"--salt", "-",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup verify failed: %v\n%s", err, string(out))
	}
}
