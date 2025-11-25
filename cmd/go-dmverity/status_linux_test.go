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
	"os/exec"
	"strings"
	"testing"

	"github.com/containerd/go-dmverity/pkg/utils"
)

func TestStatus_DeviceStatus(t *testing.T) {
	utils.RequireTool(t, "veritysetup")
	utils.RequireTool(t, "dmsetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)
	dmCleanup := utils.NewDMDeviceCleanup(t)
	defer dmCleanup.Cleanup()

	d, dCleanup, err := utils.SetupLoopDevice(data)
	if err != nil {
		t.Fatalf("failed to setup data loop: %v", err)
	}
	defer dCleanup()

	h, hCleanup, err := utils.SetupLoopDevice(hash)
	if err != nil {
		t.Fatalf("failed to setup hash loop: %v", err)
	}
	defer hCleanup()

	name := dmCleanup.Add("vgo-status-go")
	params := utils.DefaultVerityTestParams()
	utils.OpenVerityDevice(t, params, d, name, h, rootHex)

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

func TestStatus_CrossImplementation(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "veritysetup")
	utils.RequireTool(t, "dmsetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)
	dmCleanup := utils.NewDMDeviceCleanup(t)
	defer dmCleanup.Cleanup()

	params := utils.DefaultVerityTestParams()
	name := dmCleanup.Add("vgo-status-cross")
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

	argsOpen := params.BuildCVeritysetupOpenArgs(dataLoop, name, hashLoop, rootHex)
	if out, err := exec.Command("veritysetup", argsOpen...).CombinedOutput(); err != nil {
		t.Fatalf("veritysetup open failed: %v\n%s", err, string(out))
	}

	outGo, _ := utils.RunGoCLI(t, "status", name)
	outCBytes, err := exec.Command("veritysetup", "status", name).CombinedOutput()
	if err != nil {
		t.Fatalf("veritysetup status failed: %v\n%s", err, string(outCBytes))
	}
	outC := string(outCBytes)

	if strings.TrimSpace(outGo) == "" {
		t.Fatalf("empty go-dmverity status output")
	}
	if strings.TrimSpace(outC) == "" {
		t.Fatalf("empty veritysetup status output")
	}

	goFirst := utils.FirstLine(outGo)
	cFirst := utils.FirstLine(outC)
	if strings.TrimSpace(goFirst) != strings.TrimSpace(cFirst) {
		t.Fatalf("status first line mismatch on cross implementation\nGo: %q\nC:  %q\n[Go]\n%s\n[C]\n%s", goFirst, cFirst, outGo, outC)
	}

	if out, err := exec.Command("veritysetup", "close", name).CombinedOutput(); err != nil {
		t.Fatalf("veritysetup close failed: %v\n%s", err, string(out))
	}
	utils.VerifyDeviceRemoved(t, name)
}

func TestStatus_ActiveDevice(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "dmsetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)
	dmCleanup := utils.NewDMDeviceCleanup(t)
	defer dmCleanup.Cleanup()

	d, dCleanup, err := utils.SetupLoopDevice(data)
	if err != nil {
		t.Fatalf("failed to setup data loop: %v", err)
	}
	defer dCleanup()

	h, hCleanup, err := utils.SetupLoopDevice(hash)
	if err != nil {
		t.Fatalf("failed to setup hash loop: %v", err)
	}
	defer hCleanup()

	name := dmCleanup.Add("vgo-status-active")
	params := utils.DefaultVerityTestParams()
	utils.OpenVerityDevice(t, params, d, name, h, rootHex)

	outGo, _ := utils.RunGoCLI(t, "status", name)
	if !strings.Contains(outGo, "active") {
		t.Errorf("expected 'active' in status output, got: %s", outGo)
	}
	if !strings.Contains(outGo, name) {
		t.Errorf("expected device name %s in status output, got: %s", name, outGo)
	}
}

func TestStatus_InactiveDevice(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "dmsetup")

	name := "vgo-status-nonexistent"
	cmd := exec.Command("go-dmverity", "status", name)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected error for non-existent device, got output: %s", string(out))
	}
}

func TestParseStatusArgs_InvalidArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no arguments",
			args: []string{},
		},
		{
			name: "too many arguments",
			args: []string{"name1", "name2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseStatusArgs(tt.args)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
