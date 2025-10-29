//go:build linux

package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
)

func TestOpen_ParityTable(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "veritysetup")
	utils.RequireTool(t, "dmsetup")
	utils.RequireTool(t, "losetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)
	dataLoop := utils.SetupLoop(t, data)
	defer utils.DetachLoop(t, dataLoop)
	hashLoop := utils.SetupLoop(t, hash)
	defer utils.DetachLoop(t, hashLoop)

	// Open via veritysetup-go
	nameGo := "vgo-parity-go"
	_, _ = utils.RunGoCLI(t, "open", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", dataLoop, nameGo, hashLoop, rootHex)
	defer func() {
		if err := exec.Command("dmsetup", "remove", nameGo).Run(); err != nil {
			t.Logf("dmsetup remove %s: %v", nameGo, err)
		}
	}()
	// Capture our dm table for diagnostics
	tblGo, _ := utils.RunCmd(t, "dmsetup", "table", nameGo)

	// Open via veritysetup (C) with verbose debug for diagnostics
	dataLoop2 := utils.SetupLoop(t, data)
	defer utils.DetachLoop(t, dataLoop2)
	hashLoop2 := utils.SetupLoop(t, hash)
	defer utils.DetachLoop(t, hashLoop2)

	nameC := "vgo-parity-c"
	cmd := exec.Command(
		"veritysetup", "--debug", "--verbose", "open",
		dataLoop2, nameC, hashLoop2, rootHex,
		"--hash", "sha256",
		"--data-block-size", "4096",
		"--hash-block-size", "4096",
		"--salt", "-",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup open failed: %v\n[veritysetup output]\n%s\n[our dm table]\n%s", err, string(out), utils.MaskVerityDevices(tblGo))
	}
	defer func() {
		if err := exec.Command("dmsetup", "remove", nameC).Run(); err != nil {
			t.Logf("dmsetup remove %s: %v", nameC, err)
		}
	}()

	// Compare dmsetup table outputs
	outGo, _ := utils.RunCmd(t, "dmsetup", "table", nameGo)
	outC2, _ := utils.RunCmd(t, "dmsetup", "table", nameC)

	maskedGo := utils.MaskVerityDevices(outGo)
	maskedC := utils.MaskVerityDevices(outC2)

	if normalizeWS(maskedGo) != normalizeWS(maskedC) {
		t.Fatalf("dm table mismatch (excluding device tokens)\ngo: %s\nc:  %s", outGo, outC2)
	}
}

func normalizeWS(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}
