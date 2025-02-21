package verity

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runVeritySetup executes the veritysetup command
func runVeritySetup(args ...string) (string, error) {
	cmd := exec.Command("veritysetup", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func TestCompareWithVeritySetup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// Create test devices
	dataDevice, err := createTestDevice(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to create test device: %v", err)
	}
	defer os.Remove(dataDevice)

	hashDevice, err := createTestDevice(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to create test device: %v", err)
	}
	defer os.Remove(hashDevice)

	// Create test params
	params := createTestParams()

	// Format using veritysetup
	output, err := runVeritySetup("format",
		dataDevice,
		hashDevice,
		"--hash", params.HashName,
		"--data-block-size", fmt.Sprintf("%d", params.DataBlockSize),
		"--hash-block-size", fmt.Sprintf("%d", params.HashBlockSize),
		"--salt", hex.EncodeToString(params.Salt),
	)
	if err != nil {
		t.Fatalf("veritysetup format failed: %v\nOutput: %s", err, output)
	}

	// Parse root hash from veritysetup output
	var verityRootHash string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Root hash:") {
			verityRootHash = strings.TrimSpace(strings.TrimPrefix(line, "Root hash:"))
			break
		}
	}

	// Create hash using our implementation
	vh := NewVerityHash(params, dataDevice, hashDevice, make([]byte, 32))
	if err := vh.Create(); err != nil {
		t.Fatalf("Failed to create hash: %v", err)
	}

	// Compare root hashes
	ourRootHash := hex.EncodeToString(vh.rootHash)
	if ourRootHash != verityRootHash {
		t.Errorf("Root hash mismatch:\nGot:  %s\nWant: %s", ourRootHash, verityRootHash)
	}

	// Verify using veritysetup
	output, err = runVeritySetup("verify",
		dataDevice,
		hashDevice,
		verityRootHash,
		"--hash", params.HashName,
		"--data-block-size", fmt.Sprintf("%d", params.DataBlockSize),
		"--hash-block-size", fmt.Sprintf("%d", params.HashBlockSize),
		"--salt", hex.EncodeToString(params.Salt),
	)
	if err != nil {
		t.Errorf("veritysetup verify failed: %v\nOutput: %s", err, output)
	}

	// Modify data and verify failure
	f, err := os.OpenFile(dataDevice, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("Failed to open data device: %v", err)
	}
	f.WriteAt([]byte{0xFF}, 1000)
	f.Close()

	// Verify failure with veritysetup
	_, err = runVeritySetup("verify",
		dataDevice,
		hashDevice,
		verityRootHash,
		"--hash", params.HashName,
		"--data-block-size", fmt.Sprintf("%d", params.DataBlockSize),
		"--hash-block-size", fmt.Sprintf("%d", params.HashBlockSize),
		"--salt", hex.EncodeToString(params.Salt),
	)
	if err == nil {
		t.Error("veritysetup verify should fail with modified data")
	}

	// Verify failure with our implementation
	if err := vh.Verify(); err == nil {
		t.Error("Our verify should fail with modified data")
	}
}

// TestCompareDeviceActivation tests device activation comparison
func TestCompareDeviceActivation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// Create test devices
	dataDevice, err := createTestDevice(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to create test device: %v", err)
	}
	defer os.Remove(dataDevice)

	hashDevice, err := createTestDevice(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to create test device: %v", err)
	}
	defer os.Remove(hashDevice)

	// Create test params
	params := createTestParams()

	// Create hash
	vh := NewVerityHash(params, dataDevice, hashDevice, make([]byte, 32))
	if err := vh.Create(); err != nil {
		t.Fatalf("Failed to create hash: %v", err)
	}

	// Activate using veritysetup
	deviceName := "test-verity-compare"
	output, err := runVeritySetup("create",
		deviceName,
		dataDevice,
		hashDevice,
		hex.EncodeToString(vh.rootHash),
		"--hash", params.HashName,
		"--data-block-size", fmt.Sprintf("%d", params.DataBlockSize),
		"--hash-block-size", fmt.Sprintf("%d", params.HashBlockSize),
		"--salt", hex.EncodeToString(params.Salt),
	)
	if err != nil {
		t.Fatalf("veritysetup create failed: %v\nOutput: %s", err, output)
	}
	defer runVeritySetup("close", deviceName)

	// Verify device exists
	if _, err := os.Stat("/dev/mapper/" + deviceName); os.IsNotExist(err) {
		t.Fatal("Verity device was not created by veritysetup")
	}

	// Now try with our implementation
	deviceName = "test-verity-ours"
	err = CreateVerityDevice(deviceName, params, dataDevice, hashDevice, vh.rootHash)
	if err != nil {
		t.Fatalf("Our CreateVerityDevice failed: %v", err)
	}
	defer RemoveVerityDevice(deviceName)

	if _, err := os.Stat("/dev/mapper/" + deviceName); os.IsNotExist(err) {
		t.Fatal("Verity device was not created by our implementation")
	}
}
