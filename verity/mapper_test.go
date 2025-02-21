package verity

import (
	"os"
	"testing"
	"time"
)

func TestVerityMapper(t *testing.T) {
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

	// Create device mapper device
	deviceName := "test-verity"
	err = CreateVerityDevice(deviceName, params, dataDevice, hashDevice, vh.rootHash)
	if err != nil {
		t.Fatalf("Failed to create verity device: %v", err)
	}
	defer RemoveVerityDevice(deviceName)

	// Wait for device to be created
	time.Sleep(time.Second)

	// Verify device exists
	if _, err := os.Stat("/dev/mapper/" + deviceName); os.IsNotExist(err) {
		t.Fatal("Verity device was not created")
	}

	// Try to read from device
	f, err := os.Open("/dev/mapper/" + deviceName)
	if err != nil {
		t.Fatalf("Failed to open verity device: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 4096)
	if _, err := f.Read(buf); err != nil {
		t.Fatalf("Failed to read from verity device: %v", err)
	}

	// Modify data device and verify read failure
	df, err := os.OpenFile(dataDevice, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("Failed to open data device: %v", err)
	}
	df.WriteAt([]byte{0xFF}, 1000)
	df.Close()

	if _, err := f.ReadAt(buf, 0); err == nil {
		t.Fatal("Read should fail with modified data")
	}
}
