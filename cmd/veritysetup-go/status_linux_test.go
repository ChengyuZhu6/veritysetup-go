//go:build linux

package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
)

func TestStatus_DeviceStatus(t *testing.T) {
	utils.RequireTool(t, "veritysetup")
	utils.RequireTool(t, "dmsetup")
	utils.RequireTool(t, "losetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)
	d := utils.SetupLoop(t, data)
	defer utils.DetachLoop(t, d)
	h := utils.SetupLoop(t, hash)
	defer utils.DetachLoop(t, h)

	name := "vgo-status-go"
	_, _ = utils.RunGoCLI(t, "open", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", d, name, h, rootHex)
	defer func() {
		if err := exec.Command("dmsetup", "remove", name).Run(); err != nil {
			t.Logf("dmsetup remove %s: %v", name, err)
		}
	}()

	// Compare first line parity with veritysetup
	outGo, _ := utils.RunGoCLI(t, "status", name)
	outCBytes, _ := exec.Command("veritysetup", "status", name).CombinedOutput()
	outC := string(outCBytes)
	if strings.TrimSpace(outGo) == "" {
		t.Fatalf("empty our status output")
	}
	if strings.TrimSpace(outC) == "" {
		t.Fatalf("empty veritysetup status output")
	}
	goFirst := utils.FirstLine(outGo)
	cFirst := utils.FirstLine(outC)
	if strings.TrimSpace(goFirst) != strings.TrimSpace(cFirst) {
		t.Fatalf("status first line mismatch\nGo: %q\nC:  %q\n[Go]\n%s\n[C]\n%s", goFirst, cFirst, outGo, outC)
	}
}
