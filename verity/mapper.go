package verity

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	// Device mapper ioctls
	DM_IOCTL          = 0xfd
	DM_VERSION_CMD    = 0x00
	DM_TABLE_LOAD_CMD = 0x02
	DM_DEV_CREATE_CMD = 0x03
	DM_DEV_REMOVE_CMD = 0x04
	DM_DEV_STATUS_CMD = 0x07
	DM_DEV_WAIT_CMD   = 0x08
	DM_TARGET_MSG_CMD = 0x0C

	// Device mapper flags
	DM_READONLY_FLAG       = 1 << 0
	DM_SUSPEND_FLAG        = 1 << 1
	DM_EXISTS_FLAG         = 1 << 2
	DM_PERSISTENT_DEV_FLAG = 1 << 3

	// Device mapper target types
	DM_VERITY_TARGET = "verity"

	// Device mapper version info
	DM_VERSION_MAJOR = 4
	DM_VERSION_MINOR = 0
	DM_VERSION_PATCH = 0

	// Device mapper ioctl parameters
	DM_NAME_LEN    = 128
	DM_UUID_LEN    = 129
	DM_TARGET_SPEC = 98
	DM_TARGET_DEPS = 100
	DM_TARGET_MSG  = 101

	// Device mapper ioctl data sizes
	DM_VERSION_SIZE = 16
)

// DMDevice represents a device mapper device
type DMDevice struct {
	Name  string
	UUID  string
	Flags uint32
	DevNo uint64
}

// DMTarget represents a device mapper target
type DMTarget struct {
	Type   string
	Start  uint64
	Length uint64
	Params string
}

// VerityTarget represents a verity target parameters
type VerityTarget struct {
	Version       uint32
	DataDevice    string
	HashDevice    string
	DataBlockSize uint32
	HashBlockSize uint32
	NumDataBlocks uint64
	HashStart     uint64
	Algorithm     string
	Digest        string
	Salt          string
}

// dmIoctlData represents the common header for all device mapper ioctl data
type dmIoctlData struct {
	Version     [3]uint32
	DataSize    uint32
	DataStart   uint32
	TargetCount uint32
	OpenCount   int32
	Flags       uint32
	EventNr     uint32
	Name        [DM_NAME_LEN]byte
	UUID        [DM_UUID_LEN]byte
	DevNo       [2]uint32 // Major and minor device numbers
}

// dmTargetSpec represents a device mapper target specification
type dmTargetSpec struct {
	SectorStart uint64
	Length      uint64
	Status      int32
	Next        uint32
	TargetType  [DM_NAME_LEN]byte
	String      [0]byte
}

// dmIoctl performs device mapper ioctl
func dmIoctl(cmd uint32, data unsafe.Pointer) error {
	fd, err := os.OpenFile("/dev/mapper/control", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer fd.Close()

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), uintptr(cmd), uintptr(data))
	if errno != 0 {
		return errno
	}
	return nil
}

// CreateVerityDevice creates a new verity device
func CreateVerityDevice(name string, params *VerityParams, dataDevice string, hashDevice string, rootHash []byte) error {
	// Create device mapper device
	dev := &DMDevice{
		Name:  name,
		Flags: DM_READONLY_FLAG,
	}

	// Create verity target
	target := &VerityTarget{
		Version:       1,
		DataDevice:    dataDevice,
		HashDevice:    hashDevice,
		DataBlockSize: params.DataBlockSize,
		HashBlockSize: params.HashBlockSize,
		NumDataBlocks: params.DataSize,
		HashStart:     params.HashAreaOffset,
		Algorithm:     params.HashName,
		Digest:        fmt.Sprintf("%x", rootHash),
		Salt:          fmt.Sprintf("%x", params.Salt),
	}

	// Format target parameters string
	targetParams := fmt.Sprintf("%d %s %s %d %d %d %d %s %s %s",
		target.Version,
		target.DataDevice,
		target.HashDevice,
		target.DataBlockSize,
		target.HashBlockSize,
		target.NumDataBlocks,
		target.HashStart,
		target.Algorithm,
		target.Digest,
		target.Salt,
	)

	dmTarget := &DMTarget{
		Type:   DM_VERITY_TARGET,
		Start:  0,
		Length: params.DataSize * uint64(params.DataBlockSize) / 512,
		Params: targetParams,
	}

	// Create device
	if err := createDevice(dev); err != nil {
		return fmt.Errorf("failed to create device: %v", err)
	}

	// Load table
	if err := loadTable(dev, []*DMTarget{dmTarget}); err != nil {
		removeDevice(dev)
		return fmt.Errorf("failed to load table: %v", err)
	}

	return nil
}

// RemoveVerityDevice removes a verity device
func RemoveVerityDevice(name string) error {
	dev := &DMDevice{
		Name: name,
	}
	return removeDevice(dev)
}

// createDevice creates a new device mapper device
func createDevice(dev *DMDevice) error {
	// Calculate required size for ioctl data
	size := unsafe.Sizeof(dmIoctlData{})
	data := make([]byte, size)
	header := (*dmIoctlData)(unsafe.Pointer(&data[0]))

	// Fill header
	header.Version[0] = DM_VERSION_MAJOR
	header.Version[1] = DM_VERSION_MINOR
	header.Version[2] = DM_VERSION_PATCH
	header.DataSize = uint32(size)
	header.DataStart = uint32(size)
	header.Flags = dev.Flags

	// Copy device name
	copy(header.Name[:], dev.Name)
	if dev.UUID != "" {
		copy(header.UUID[:], dev.UUID)
	}

	// Create device
	cmd := ((DM_IOCTL << 0x8) | DM_DEV_CREATE_CMD)
	if err := dmIoctl(uint32(cmd), unsafe.Pointer(&data[0])); err != nil {
		return fmt.Errorf("device mapper ioctl failed: %v", err)
	}

	// Get device number
	dev.DevNo = uint64(header.DevNo[0])<<32 | uint64(header.DevNo[1])

	return nil
}

// removeDevice removes a device mapper device
func removeDevice(dev *DMDevice) error {
	// Calculate required size for ioctl data
	size := unsafe.Sizeof(dmIoctlData{})
	data := make([]byte, size)
	header := (*dmIoctlData)(unsafe.Pointer(&data[0]))

	// Fill header
	header.Version[0] = DM_VERSION_MAJOR
	header.Version[1] = DM_VERSION_MINOR
	header.Version[2] = DM_VERSION_PATCH
	header.DataSize = uint32(size)
	header.DataStart = uint32(size)
	header.Flags = dev.Flags

	// Copy device name
	copy(header.Name[:], dev.Name)

	// Remove device
	cmd := ((DM_IOCTL << 0x8) | DM_DEV_REMOVE_CMD)
	if err := dmIoctl(uint32(cmd), unsafe.Pointer(&data[0])); err != nil {
		return fmt.Errorf("device mapper ioctl failed: %v", err)
	}

	return nil
}

// loadTable loads the device mapper table
func loadTable(dev *DMDevice, targets []*DMTarget) error {
	// Calculate total size needed for ioctl data
	size := unsafe.Sizeof(dmIoctlData{})
	for _, target := range targets {
		size += unsafe.Sizeof(dmTargetSpec{})
		size += uintptr(len(target.Params) + 1) // +1 for null terminator
	}

	// Allocate memory
	data := make([]byte, size)
	header := (*dmIoctlData)(unsafe.Pointer(&data[0]))

	// Fill header
	header.Version[0] = DM_VERSION_MAJOR
	header.Version[1] = DM_VERSION_MINOR
	header.Version[2] = DM_VERSION_PATCH
	header.DataSize = uint32(size)
	header.DataStart = uint32(unsafe.Sizeof(dmIoctlData{}))
	header.TargetCount = uint32(len(targets))
	header.Flags = dev.Flags

	// Copy device name
	copy(header.Name[:], dev.Name)

	// Fill target specifications
	offset := unsafe.Sizeof(dmIoctlData{})
	for _, target := range targets {
		spec := (*dmTargetSpec)(unsafe.Pointer(&data[offset]))
		spec.SectorStart = target.Start
		spec.Length = target.Length
		copy(spec.TargetType[:], target.Type)

		// Copy target parameters
		paramOffset := offset + unsafe.Sizeof(dmTargetSpec{})
		copy(data[paramOffset:], target.Params)
		data[paramOffset+uintptr(len(target.Params))] = 0 // null terminator

		offset += unsafe.Sizeof(dmTargetSpec{}) + uintptr(len(target.Params)+1)
	}

	// Load table
	cmd := ((DM_IOCTL << 0x8) | DM_TABLE_LOAD_CMD)
	if err := dmIoctl(uint32(cmd), unsafe.Pointer(&data[0])); err != nil {
		return fmt.Errorf("device mapper ioctl failed: %v", err)
	}

	return nil
}
