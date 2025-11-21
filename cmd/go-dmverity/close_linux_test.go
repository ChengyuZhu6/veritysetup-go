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

func TestClose(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "veritysetup")
	utils.RequireTool(t, "dmsetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)

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

	params := utils.DefaultVerityTestParams()

	nameGo := "vgo-close-go"
	utils.OpenVerityDevice(t, params, d, nameGo, h, rootHex)
	_, _ = utils.RunGoCLI(t, "close", nameGo)
	utils.VerifyDeviceRemoved(t, nameGo)

	nameC := "vgo-close-c"
	args := params.BuildCVeritysetupOpenArgs(d, nameC, h, rootHex)
	if out, err := exec.Command("veritysetup", args...).CombinedOutput(); err != nil {
		t.Fatalf("veritysetup open failed: %v\n%s", err, string(out))
	}
	if out, err := exec.Command("veritysetup", "close", nameC).CombinedOutput(); err != nil {
		t.Fatalf("veritysetup close failed: %v\n%s", err, string(out))
	}
	utils.VerifyDeviceRemoved(t, nameC)
}

func TestClose_CrossImplementation(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "veritysetup")
	utils.RequireTool(t, "dmsetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)
	dmCleanup := utils.NewDMDeviceCleanup(t)
	defer dmCleanup.Cleanup()

	params := utils.DefaultVerityTestParams()

	nameCGo := dmCleanup.Add("vgo-close-cross-c-go")
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
	argsOpen := params.BuildCVeritysetupOpenArgs(dataLoop, nameCGo, hashLoop, rootHex)
	if out, err := exec.Command("veritysetup", argsOpen...).CombinedOutput(); err != nil {
		t.Fatalf("veritysetup open failed: %v\n%s", err, string(out))
	}
	_, _ = utils.RunGoCLI(t, "close", nameCGo)
	utils.VerifyDeviceRemoved(t, nameCGo)

	nameGoC := dmCleanup.Add("vgo-close-cross-go-c")
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
	utils.OpenVerityDevice(t, params, dataLoop2, nameGoC, hashLoop2, rootHex)
	if out, err := exec.Command("veritysetup", "close", nameGoC).CombinedOutput(); err != nil {
		t.Fatalf("veritysetup close failed: %v\n%s", err, string(out))
	}
	utils.VerifyDeviceRemoved(t, nameGoC)
}

func TestClose_ActiveDevice(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "dmsetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)

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

	name := "vgo-close-active"
	params := utils.DefaultVerityTestParams()
	utils.OpenVerityDevice(t, params, d, name, h, rootHex)

	outClose, _ := utils.RunGoCLI(t, "close", name)
	if !strings.Contains(outClose, "removed") {
		t.Errorf("expected 'removed' in close output, got: %s", outClose)
	}

	utils.VerifyDeviceRemoved(t, name)
}

func TestClose_NonExistentDevice(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "dmsetup")

	name := "vgo-close-nonexistent"
	cmd := exec.Command("go-dmverity", "close", name)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected error for non-existent device, got output: %s", string(out))
	}
}

func TestClose_MultipleDevices(t *testing.T) {
	utils.RequireRoot(t)
	utils.RequireTool(t, "dmsetup")

	data, hash, rootHex := utils.CreateFormattedFiles(t)

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

	params := utils.DefaultVerityTestParams()
	names := []string{"vgo-close-multi1", "vgo-close-multi2"}
	for _, name := range names {
		utils.OpenVerityDevice(t, params, d, name, h, rootHex)
	}

	for _, name := range names {
		_, _ = utils.RunGoCLI(t, "close", name)
		utils.VerifyDeviceRemoved(t, name)
	}
}

func TestParseCloseArgs_InvalidArgs(t *testing.T) {
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
			_, err := parseCloseArgs(tt.args)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
