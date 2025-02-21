package verity

import (
	"fmt"
	"os"
	"strings"
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

	// Create verity device with a unique name
	deviceName := fmt.Sprintf("verity-%d", time.Now().Unix())
	if err := CreateVerityDevice(deviceName, params, dataDevice, hashDevice, vh.rootHash); err != nil {
		t.Fatalf("Failed to create verity device: %v", err)
	}
	defer RemoveVerityDevice(deviceName)

	// Wait for device to be created
	time.Sleep(time.Second)

	// Verify device exists
	if _, err := os.Stat(fmt.Sprintf("/dev/mapper/%s", deviceName)); err != nil {
		t.Errorf("Device file not found: %v", err)
	}

	// Remove device
	if err := RemoveVerityDevice(deviceName); err != nil {
		t.Errorf("Failed to remove verity device: %v", err)
	}

	// Verify device is removed
	if _, err := os.Stat(fmt.Sprintf("/dev/mapper/%s", deviceName)); !os.IsNotExist(err) {
		t.Errorf("Device file still exists after removal")
	}
}

func TestVerityMapperErrors(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	tests := []struct {
		name       string
		deviceName string
		wantErr    bool
	}{
		{
			name:       "Empty device name",
			deviceName: "",
			wantErr:    true,
		},
		{
			name:       "Very long device name",
			deviceName: strings.Repeat("v", DM_NAME_LEN+1),
			wantErr:    true,
		},
		{
			name:       "Invalid characters",
			deviceName: "test/device",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := createTestParams()
			err := CreateVerityDevice(tt.deviceName, params, "/dev/null", "/dev/null", make([]byte, 32))
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateVerityDevice() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
