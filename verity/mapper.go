package verity

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	// Device mapper ioctls
	DM_IOCTL           = 0xfd
	DM_VERSION_CMD     = 0x00
	DM_TABLE_LOAD_CMD  = 0x02
	DM_DEV_CREATE_CMD  = 0x03
	DM_DEV_REMOVE_CMD  = 0x04
	DM_DEV_SUSPEND_CMD = 0x05
	DM_DEV_STATUS_CMD  = 0x07
	DM_DEV_WAIT_CMD    = 0x08
	DM_TARGET_MSG_CMD  = 0x0C

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
	DM_STRUCT_SIZE  = 312 // Size of dm_ioctl struct in kernel
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
	DevNo       uint64 // Device number
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

	// Get the header
	header := (*dmIoctlData)(data)

	// Debug info
	fmt.Printf("DM ioctl command: 0x%x\n", cmd)
	fmt.Printf("DM ioctl header:\n")
	fmt.Printf("  Version: %d.%d.%d\n", header.Version[0], header.Version[1], header.Version[2])
	fmt.Printf("  DataSize: %d\n", header.DataSize)
	fmt.Printf("  DataStart: %d\n", header.DataStart)
	fmt.Printf("  TargetCount: %d\n", header.TargetCount)
	fmt.Printf("  Flags: 0x%x\n", header.Flags)
	fmt.Printf("  Name: %q\n", string(header.Name[:]))
	fmt.Printf("  UUID: %q\n", string(header.UUID[:]))
	fmt.Printf("  DevNo: %d\n", header.DevNo)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd.Fd(),
		uintptr(cmd),
		uintptr(data),
	)

	if errno != 0 {
		fmt.Printf("DM ioctl failed with errno: %d (%v)\n", errno, errno)
		if errno == syscall.EEXIST && (header.Flags&DM_EXISTS_FLAG) != 0 {
			return nil
		}
		return errno
	}
	return nil
}

// CreateVerityDevice creates a new verity device
func CreateVerityDevice(name string, params *VerityParams, dataDevice string, hashDevice string, rootHash []byte) error {
	// Validate device name
	if name == "" {
		return fmt.Errorf("device name cannot be empty")
	}

	// Validate device name characters
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return fmt.Errorf("invalid character in device name: %c", c)
		}
	}

	// Create device mapper device
	dev := &DMDevice{
		Name:  name,
		Flags: DM_READONLY_FLAG,
		UUID:  fmt.Sprintf("CRYPT-VERITY-%x", rootHash[:8]),
	}

	// First suspend the device
	dev.Flags |= DM_SUSPEND_FLAG
	if err := suspendDevice(dev); err != nil {
		return fmt.Errorf("failed to suspend device: %v", err)
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

	// Create device in suspended state
	if err := createDevice(dev); err != nil {
		return fmt.Errorf("failed to create device: %v", err)
	}

	// Load table
	if err := loadTable(dev, []*DMTarget{dmTarget}); err != nil {
		removeDevice(dev)
		return fmt.Errorf("failed to load table: %v", err)
	}

	// Resume device after loading table
	dev.Flags = DM_READONLY_FLAG // Reset flags
	if err := resumeDevice(dev); err != nil {
		removeDevice(dev)
		return fmt.Errorf("failed to resume device: %v", err)
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
	// Use fixed size from kernel
	size := uintptr(DM_STRUCT_SIZE)

	data := make([]byte, size)
	header := (*dmIoctlData)(unsafe.Pointer(&data[0]))

	// Fill header
	header.Version[0] = DM_VERSION_MAJOR
	header.Version[1] = DM_VERSION_MINOR
	header.Version[2] = DM_VERSION_PATCH
	header.DataSize = DM_STRUCT_SIZE
	header.DataStart = uint32(size)
	header.Flags = dev.Flags

	// Copy device name
	nameBytes := []byte(dev.Name)
	if len(nameBytes) > DM_NAME_LEN-1 {
		return fmt.Errorf("device name too long")
	}
	// Clear arrays first
	for i := range header.Name {
		header.Name[i] = 0
	}
	for i := range header.UUID {
		header.UUID[i] = 0
	}

	// Copy name with explicit null termination
	if len(nameBytes) > 0 {
		copy(header.Name[:], nameBytes)
		header.Name[len(nameBytes)] = 0
	}

	if dev.UUID != "" {
		uuidBytes := []byte(dev.UUID)
		if len(uuidBytes) > DM_UUID_LEN-1 {
			return fmt.Errorf("UUID too long")
		}
		// Copy UUID with explicit null termination
		copy(header.UUID[:], uuidBytes)
		header.UUID[len(uuidBytes)] = 0
	}

	// Create device
	cmd := ((DM_IOCTL << 0x8) | DM_DEV_CREATE_CMD)
	fmt.Printf("Creating device with name: %q\n", dev.Name)
	if err := dmIoctl(uint32(cmd), unsafe.Pointer(&data[0])); err != nil {
		return fmt.Errorf("device mapper ioctl failed: %v", err)
	}

	// Get device number
	dev.DevNo = header.DevNo

	return nil
}

// removeDevice removes a device mapper device
func removeDevice(dev *DMDevice) error {
	// Use fixed size from kernel
	size := uintptr(DM_STRUCT_SIZE)

	data := make([]byte, size)
	header := (*dmIoctlData)(unsafe.Pointer(&data[0]))

	// Fill header
	header.Version[0] = DM_VERSION_MAJOR
	header.Version[1] = DM_VERSION_MINOR
	header.Version[2] = DM_VERSION_PATCH
	header.DataSize = DM_STRUCT_SIZE
	header.DataStart = uint32(size)
	header.Flags = dev.Flags

	// Copy device name
	nameBytes := []byte(dev.Name)
	if len(nameBytes) > DM_NAME_LEN-1 {
		return fmt.Errorf("device name too long")
	}
	copy(header.Name[:len(nameBytes)], nameBytes)
	header.Name[len(nameBytes)] = 0

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
	baseSize := uintptr(DM_STRUCT_SIZE)
	for _, target := range targets {
		baseSize += unsafe.Sizeof(dmTargetSpec{})
		baseSize += uintptr(len(target.Params) + 1) // +1 for null terminator
	}

	// Allocate memory
	data := make([]byte, baseSize)
	header := (*dmIoctlData)(unsafe.Pointer(&data[0]))

	// Fill header
	header.Version[0] = DM_VERSION_MAJOR
	header.Version[1] = DM_VERSION_MINOR
	header.Version[2] = DM_VERSION_PATCH
	header.DataSize = uint32(baseSize)
	header.DataStart = uint32(DM_STRUCT_SIZE)
	header.TargetCount = uint32(len(targets))
	header.Flags = dev.Flags

	// Copy device name
	nameBytes := []byte(dev.Name)
	if len(nameBytes) > DM_NAME_LEN-1 {
		return fmt.Errorf("device name too long")
	}
	// Clear arrays first
	for i := range header.Name {
		header.Name[i] = 0
	}
	for i := range header.UUID {
		header.UUID[i] = 0
	}

	// Copy name with null termination
	copy(header.Name[:], nameBytes)
	header.Name[len(nameBytes)] = 0

	// Copy UUID if present
	if dev.UUID != "" {
		uuidBytes := []byte(dev.UUID)
		if len(uuidBytes) > DM_UUID_LEN-1 {
			return fmt.Errorf("UUID too long")
		}
		copy(header.UUID[:], uuidBytes)
		header.UUID[len(uuidBytes)] = 0
	}

	// Fill target specifications
	offset := uintptr(DM_STRUCT_SIZE)
	for _, target := range targets {
		spec := (*dmTargetSpec)(unsafe.Pointer(&data[offset]))
		spec.SectorStart = target.Start
		spec.Length = target.Length
		// Clear target type array
		for i := range spec.TargetType {
			spec.TargetType[i] = 0
		}
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

func suspendDevice(dev *DMDevice) error {
	// Use fixed size from kernel
	size := uintptr(DM_STRUCT_SIZE)

	data := make([]byte, size)
	header := (*dmIoctlData)(unsafe.Pointer(&data[0]))

	// Fill header
	header.Version[0] = DM_VERSION_MAJOR
	header.Version[1] = DM_VERSION_MINOR
	header.Version[2] = DM_VERSION_PATCH
	header.DataSize = DM_STRUCT_SIZE
	header.DataStart = uint32(size)
	header.Flags = dev.Flags | DM_SUSPEND_FLAG

	// Copy device name
	nameBytes := []byte(dev.Name)
	if len(nameBytes) > DM_NAME_LEN-1 {
		return fmt.Errorf("device name too long")
	}
	copy(header.Name[:len(nameBytes)], nameBytes)
	header.Name[len(nameBytes)] = 0

	// Suspend device
	cmd := ((DM_IOCTL << 0x8) | DM_DEV_SUSPEND_CMD)
	if err := dmIoctl(uint32(cmd), unsafe.Pointer(&data[0])); err != nil {
		return fmt.Errorf("device mapper ioctl failed: %v", err)
	}

	return nil
}

func resumeDevice(dev *DMDevice) error {
	// Use fixed size from kernel
	size := uintptr(DM_STRUCT_SIZE)

	data := make([]byte, size)
	header := (*dmIoctlData)(unsafe.Pointer(&data[0]))

	// Fill header
	header.Version[0] = DM_VERSION_MAJOR
	header.Version[1] = DM_VERSION_MINOR
	header.Version[2] = DM_VERSION_PATCH
	header.DataSize = DM_STRUCT_SIZE
	header.DataStart = uint32(size)
	header.Flags = dev.Flags &^ DM_SUSPEND_FLAG

	// Copy device name
	nameBytes := []byte(dev.Name)
	if len(nameBytes) > DM_NAME_LEN-1 {
		return fmt.Errorf("device name too long")
	}
	copy(header.Name[:len(nameBytes)], nameBytes)
	header.Name[len(nameBytes)] = 0

	// Resume device
	cmd := ((DM_IOCTL << 0x8) | DM_DEV_SUSPEND_CMD)
	if err := dmIoctl(uint32(cmd), unsafe.Pointer(&data[0])); err != nil {
		return fmt.Errorf("device mapper ioctl failed: %v", err)
	}

	return nil
}
