//go:build linux

package main

import (
	"os/exec"
	"testing"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
)

func TestClose_Parity(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "veritysetup")
	utils.RequireTool(t, "dmsetup")
	utils.RequireTool(t, "losetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)
	d := utils.SetupLoop(t, data)
	defer utils.DetachLoop(t, d)
	h := utils.SetupLoop(t, hash)
	defer utils.DetachLoop(t, h)

	// Go path: open then close
	nameGo := "vgo-close-go"
	_, _ = utils.RunGoCLI(t, "open", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", d, nameGo, h, rootHex)
	_, _ = utils.RunGoCLI(t, "close", nameGo)
	// Ensure removed
	if out, err := exec.Command("dmsetup", "info", nameGo).CombinedOutput(); err == nil {
		t.Fatalf("expected %s to be removed, but dmsetup info succeeded: %s", nameGo, string(out))
	}

	// C path: open then close (enable debugging)
	nameC := "vgo-close-c"
	if out, err := exec.Command(
		"veritysetup", "--debug", "--verbose", "open",
		d, nameC, h, rootHex,
		"--hash", "sha256",
		"--data-block-size", "4096",
		"--hash-block-size", "4096",
		"--salt", "-",
	).CombinedOutput(); err != nil {
		t.Fatalf("veritysetup open failed: %v\n%s", err, string(out))
	}
	if out, err := exec.Command("veritysetup", "close", nameC).CombinedOutput(); err != nil {
		t.Fatalf("veritysetup close failed: %v\n%s", err, string(out))
	}
	if out, err := exec.Command("dmsetup", "info", nameC).CombinedOutput(); err == nil {
		t.Fatalf("expected %s to be removed, but dmsetup info succeeded: %s", nameC, string(out))
	}
}
