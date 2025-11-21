/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/containerd/go-dmverity/pkg/utils"
)

func TestOpenTable(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "veritysetup")
	utils.RequireTool(t, "dmsetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)
	dmCleanup := utils.NewDMDeviceCleanup(t)
	defer dmCleanup.Cleanup()

	dataLoop, dataLoopCleanup, err := utils.SetupLoopDevice(data)
	if err != nil {
		t.Fatalf("failed to setup data loop: %v", err)
	}
	defer dataLoopCleanup()

	hashLoop, hashLoopCleanup, err := utils.SetupLoopDevice(hash)
	if err != nil {
		t.Fatalf("failed to setup hash loop: %v", err)
	}
	defer hashLoopCleanup()

	params := utils.DefaultVerityTestParams()
	nameGo := dmCleanup.Add("vgo-parity-go")
	utils.OpenVerityDevice(t, params, dataLoop, nameGo, hashLoop, rootHex)
	tblGo, _ := utils.RunCmd(t, "dmsetup", "table", nameGo)

	dataLoop2, dataLoop2Cleanup, err := utils.SetupLoopDevice(data)
	if err != nil {
		t.Fatalf("failed to setup data loop: %v", err)
	}
	defer dataLoop2Cleanup()

	hashLoop2, hashLoop2Cleanup, err := utils.SetupLoopDevice(hash)
	if err != nil {
		t.Fatalf("failed to setup hash loop: %v", err)
	}
	defer hashLoop2Cleanup()

	nameC := dmCleanup.Add("vgo-parity-c")
	args := params.BuildCVeritysetupOpenArgs(dataLoop2, nameC, hashLoop2, rootHex)
	out, err := exec.Command("veritysetup", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup open failed: %v\n[veritysetup output]\n%s\n[our dm table]\n%s", err, string(out), utils.MaskVerityDevices(tblGo))
	}

	outGo, _ := utils.RunCmd(t, "dmsetup", "table", nameGo)
	outC2, _ := utils.RunCmd(t, "dmsetup", "table", nameC)

	maskedGo := utils.MaskVerityDevices(outGo)
	maskedC := utils.MaskVerityDevices(outC2)

	if normalizeWS(maskedGo) != normalizeWS(maskedC) {
		t.Fatalf("dm table mismatch (excluding device tokens)\ngo: %s\nc:  %s", outGo, outC2)
	}
}

func TestOpen_CrossImplementation(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "veritysetup")
	utils.RequireTool(t, "dmsetup")

	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)

	outC, err := exec.Command("veritysetup", "format", data, hash, "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-").CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup format failed: %v\n%s", err, string(outC))
	}
	rootHex := utils.ExtractRootHex(t, string(outC))

	dmCleanup := utils.NewDMDeviceCleanup(t)
	defer dmCleanup.Cleanup()

	dataLoop, dataLoopCleanup, err := utils.SetupLoopDevice(data)
	if err != nil {
		t.Fatalf("failed to setup data loop: %v", err)
	}
	defer dataLoopCleanup()

	hashLoop, hashLoopCleanup, err := utils.SetupLoopDevice(hash)
	if err != nil {
		t.Fatalf("failed to setup hash loop: %v", err)
	}
	defer hashLoopCleanup()

	name := dmCleanup.Add("vgo-open-cross")
	params := utils.DefaultVerityTestParams()

	openArgs := params.BuildOpenArgs(dataLoop, name, hashLoop, rootHex)
	_, _ = utils.RunGoCLI(t, openArgs...)

	outGo, _ := utils.RunCmd(t, "dmsetup", "info", name)
	if !strings.Contains(outGo, name) {
		t.Errorf("device %s not found in dmsetup info", name)
	}

	if out, err := exec.Command("veritysetup", "close", name).CombinedOutput(); err != nil {
		t.Fatalf("veritysetup close failed: %v\n%s", err, string(out))
	}
}

func normalizeWS(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

func TestOpen_WithSuperblock(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "dmsetup")

	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)

	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", data, hash)
	rootHex := utils.ExtractRootHex(t, outGo)

	dmCleanup := utils.NewDMDeviceCleanup(t)
	defer dmCleanup.Cleanup()

	dataLoop, dataLoopCleanup, err := utils.SetupLoopDevice(data)
	if err != nil {
		t.Fatalf("failed to setup data loop: %v", err)
	}
	defer dataLoopCleanup()

	hashLoop, hashLoopCleanup, err := utils.SetupLoopDevice(hash)
	if err != nil {
		t.Fatalf("failed to setup hash loop: %v", err)
	}
	defer hashLoopCleanup()

	name := dmCleanup.Add("vgo-open-sb")
	_, _ = utils.RunGoCLI(t, "open", dataLoop, name, hashLoop, rootHex)

	out, _ := utils.RunCmd(t, "dmsetup", "info", name)
	if !strings.Contains(out, name) {
		t.Errorf("device %s not found in dmsetup info", name)
	}
}

func TestOpen_NoSuperblock(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "dmsetup")

	data := utils.MakeTempFile(t, 4096*16)
	hash := utils.MakeTempFile(t, 0)

	outGo, _ := utils.RunGoCLI(t, "format", "--hash", "sha256", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", "--no-superblock", "--hash-offset", "0", data, hash)
	rootHex := utils.ExtractRootHex(t, outGo)

	dmCleanup := utils.NewDMDeviceCleanup(t)
	defer dmCleanup.Cleanup()

	dataLoop, dataLoopCleanup, err := utils.SetupLoopDevice(data)
	if err != nil {
		t.Fatalf("failed to setup data loop: %v", err)
	}
	defer dataLoopCleanup()

	hashLoop, hashLoopCleanup, err := utils.SetupLoopDevice(hash)
	if err != nil {
		t.Fatalf("failed to setup hash loop: %v", err)
	}
	defer hashLoopCleanup()

	name := dmCleanup.Add("vgo-open-nosb")
	params := utils.DefaultVerityTestParams()
	utils.OpenVerityDevice(t, params, dataLoop, name, hashLoop, rootHex)

	out, _ := utils.RunCmd(t, "dmsetup", "info", name)
	if !strings.Contains(out, name) {
		t.Errorf("device %s not found in dmsetup info", name)
	}
}

func TestParseOpenArgs_InvalidArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing arguments",
			args: []string{"data", "name", "hash"},
		},
		{
			name: "invalid data block size",
			args: []string{"--data-block-size", "1000", "data", "name", "hash", "root"},
		},
		{
			name: "invalid hash block size",
			args: []string{"--hash-block-size", "1000", "data", "name", "hash", "root"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, _, _, _, err := parseOpenArgs(tt.args)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestGetBlockOrFileSize(t *testing.T) {
	tmpFile := utils.MakeTempFile(t, 8192)
	defer os.Remove(tmpFile)

	size, err := utils.GetBlockOrFileSize(tmpFile)
	if err != nil {
		t.Fatalf("getBlockOrFileSize failed: %v", err)
	}

	if size != 8192 {
		t.Errorf("expected size 8192, got %d", size)
	}
}
