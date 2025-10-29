//go:build linux

package dm

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Ioctl encoding constants (see <asm-generic/ioctl.h>).
const (
	iocNRBits   = 8
	iocTypeBits = 8
	iocSizeBits = 14
	iocDirBits  = 2

	iocNRShift   = 0
	iocTypeShift = iocNRShift + iocNRBits
	iocSizeShift = iocTypeShift + iocTypeBits
	iocDirShift  = iocSizeShift + iocSizeBits

	iocWrite = 1
	iocRead  = 2
)

func ioc(dir, typ, nr, size uintptr) uintptr {
	return (dir << iocDirShift) | (typ << iocTypeShift) | (nr << iocNRShift) | (size << iocSizeShift)
}

func iowr(typ, nr, size uintptr) uintptr { return ioc(iocRead|iocWrite, typ, nr, size) }

// Device-mapper ioctl constants (see <linux/dm-ioctl.h>).
// Ioctl type ("magic").
const dmIOCTLType = 0xfd // matches Linux uapi header

// DM ioctl command numbers (subset).
const (
	cmdDMDeviceReload = 2
	cmdDMDevCreate    = 3
	cmdDMDevRemove    = 4
	cmdDMDevSuspend   = 6
	cmdDMTableClear   = 9
	cmdDMTableStatus  = 11
)

// Expected DM version.
const (
	DMVersionMajor = 4
	DMVersionMinor = 0
	DMVersionPatch = 0
)

// UAPI size limits.
const (
	DMNameLen     = 128
	DMUUIDLen     = 129
	DMMaxTypeName = 16
)

// dm_ioctl.flags bits (subset).
const (
	DMSuspendFlag     = 1 << 1
	DMNoFlushFlag     = 1 << 2
	DMStatusTableFlag = 1 << 4 // for DM_TABLE_STATUS vs DM_STATUS of live table
)

// dm_ioctl per UAPI; layout must match kernel ABI.
type dmIoctl struct {
	Version     [3]uint32
	DataSize    uint32
	DataStart   uint32
	TargetCount uint32
	OpenCount   int32
	Flags       uint32
	EventNr     uint32
	Padding     uint32
	Dev         uint64
	Name        [DMNameLen]byte
	UUID        [DMUUIDLen]byte
	_           [7]byte // aligns struct to 8 and matches kernel size
}

// dm_target_spec per UAPI.
type dmTargetSpec struct {
	SectorStart uint64
	Length      uint64
	Status      int32
	Next        uint32
	TargetType  [DMMaxTypeName]byte
}

// Control wraps /dev/mapper/control.
type Control struct {
	fd *os.File
}

// Open the control device.
func Open() (*Control, error) {
	// Go sets CLOEXEC on file descriptors by default; no need to pass O_CLOEXEC.
	fd, err := os.OpenFile("/dev/mapper/control", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &Control{fd: fd}, nil
}

// Close control fd.
func (c *Control) Close() error {
	if c == nil || c.fd == nil {
		return nil
	}
	return c.fd.Close()
}

var ioctlSyscall = func(fd, req, arg uintptr) (uintptr, uintptr, unix.Errno) {
	return unix.Syscall(unix.SYS_IOCTL, fd, req, arg)
}

func dmReq(nr uintptr) uintptr {
	return iowr(dmIOCTLType, nr, uintptr(unsafe.Sizeof(dmIoctl{})))
}

func (c *Control) rawIoctl(nr uintptr, buf unsafe.Pointer) error {
	_, _, errno := ioctlSyscall(c.fd.Fd(), dmReq(nr), uintptr(buf))
	if errno != 0 {
		return errno
	}
	return nil
}

func makeBaseIoctl(name, uuid string, totalDataSize int) dmIoctl {
	var io dmIoctl
	io.Version[0] = DMVersionMajor
	io.Version[1] = DMVersionMinor
	io.Version[2] = DMVersionPatch
	io.DataSize = uint32(totalDataSize)
	io.DataStart = uint32(unsafe.Sizeof(dmIoctl{}))
	copy(io.Name[:], []byte(name))
	copy(io.UUID[:], []byte(uuid))
	return io
}

// Create a mapped device by name; returns dev_t.
func (c *Control) CreateDevice(name string) (uint64, error) {
	// Kernel copies name from dm_ioctl. No payload area needed for create.
	buf := make([]byte, unsafe.Sizeof(dmIoctl{}))
	io := (*dmIoctl)(unsafe.Pointer(&buf[0]))
	*io = makeBaseIoctl(name, "", int(len(buf)))
	if err := c.rawIoctl(cmdDMDevCreate, unsafe.Pointer(io)); err != nil {
		return 0, fmt.Errorf("dm create '%s': %w", name, err)
	}
	return io.Dev, nil
}

// Remove an inactive or suspended device by name.
func (c *Control) RemoveDevice(name string) error {
	buf := make([]byte, unsafe.Sizeof(dmIoctl{}))
	io := (*dmIoctl)(unsafe.Pointer(&buf[0]))
	*io = makeBaseIoctl(name, "", int(len(buf)))
	if err := c.rawIoctl(cmdDMDevRemove, unsafe.Pointer(io)); err != nil {
		return fmt.Errorf("dm remove '%s': %w", name, err)
	}
	return nil
}

// Suspend (suspend=true) or resume (suspend=false) a device.
func (c *Control) SuspendDevice(name string, suspend bool) error {
	buf := make([]byte, unsafe.Sizeof(dmIoctl{}))
	io := (*dmIoctl)(unsafe.Pointer(&buf[0]))
	*io = makeBaseIoctl(name, "", int(len(buf)))
	if suspend {
		io.Flags |= DMSuspendFlag
	}
	if err := c.rawIoctl(cmdDMDevSuspend, unsafe.Pointer(io)); err != nil {
		return fmt.Errorf("dm suspend/resume '%s': %w", name, err)
	}
	return nil
}

// Suspend without flushing in-flight I/O.
func (c *Control) SuspendDeviceNoFlush(name string) error {
	buf := make([]byte, unsafe.Sizeof(dmIoctl{}))
	io := (*dmIoctl)(unsafe.Pointer(&buf[0]))
	*io = makeBaseIoctl(name, "", int(len(buf)))
	io.Flags |= DMSuspendFlag | DMNoFlushFlag
	if err := c.rawIoctl(cmdDMDevSuspend, unsafe.Pointer(io)); err != nil {
		return fmt.Errorf("dm suspend(noflush) '%s': %w", name, err)
	}
	return nil
}

// A single table target.
type Target struct {
	SectorStart uint64
	Length      uint64
	Type        string // e.g. "verity"
	Params      string // target-specific parameters string
}

// Load the provided targets into the inactive table (via DM_DEVICE_RELOAD).
func (c *Control) LoadTable(name string, targets []Target) error {
	if len(targets) == 0 {
		return errors.New("no targets provided")
	}

	// Estimate payload size: each target spec + params + padding.
	// Start with dm_ioctl header.
	headerSize := int(unsafe.Sizeof(dmIoctl{}))
	payload := make([]byte, 0, headerSize+len(targets)*(int(unsafe.Sizeof(dmTargetSpec{}))+256))
	// Build body in a temporary slice, then prepend dm_ioctl.
	body := make([]byte, 0, cap(payload)-headerSize)
	for i, t := range targets {
		// Append dm_target_spec
		start := len(body)
		body = append(body, make([]byte, int(unsafe.Sizeof(dmTargetSpec{})))...)
		spec := (*dmTargetSpec)(unsafe.Pointer(&body[start]))
		spec.SectorStart = t.SectorStart
		spec.Length = t.Length
		spec.Status = 0
		spec.Next = 0 // last target's next remains 0; kernel ignores for last
		copy(spec.TargetType[:], []byte(t.Type))

		// Append params string (NUL-terminated), then 8-byte pad
		paramsBytes := append([]byte(t.Params), 0)
		body = append(body, paramsBytes...)
		// pad to 8-byte boundary from start of this spec
		rel := len(body) - start
		pad := ((rel + 7) &^ 7) - rel
		if pad > 0 {
			body = append(body, make([]byte, pad)...)
		}
		// For non-last targets, set Next to offset to following spec
		if i < len(targets)-1 {
			spec.Next = uint32(len(body) - start)
		}
	}

	// Allocate final buffer and place dm_ioctl header at front
	buf := make([]byte, headerSize+len(body))
	io := (*dmIoctl)(unsafe.Pointer(&buf[0]))
	*io = makeBaseIoctl(name, "", len(buf))
	io.TargetCount = uint32(len(targets))
	copy(buf[headerSize:], body)

	if err := c.rawIoctl(cmdDMDeviceReload, unsafe.Pointer(io)); err != nil {
		return fmt.Errorf("dm table load '%s': %w", name, err)
	}
	return nil
}

// Clear the inactive table for the given device name.
func (c *Control) ClearTable(name string) error {
	buf := make([]byte, unsafe.Sizeof(dmIoctl{}))
	io := (*dmIoctl)(unsafe.Pointer(&buf[0]))
	*io = makeBaseIoctl(name, "", int(len(buf)))
	if err := c.rawIoctl(cmdDMTableClear, unsafe.Pointer(io)); err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENXIO) {
			return nil
		}
		return fmt.Errorf("dm table clear '%s': %w", name, err)
	}
	return nil
}

// Query status; inactive=true sets DMStatusTableFlag. Returns raw target status lines joined with '\n'.
func (c *Control) TableStatus(name string, inactive bool) (string, error) {
	// Start with a reasonable buffer; kernel returns -ENOSPC if too small.
	bufSz := 16 * 1024
	for tries := 0; tries < 3; tries++ {
		buf := make([]byte, bufSz)
		io := (*dmIoctl)(unsafe.Pointer(&buf[0]))
		*io = makeBaseIoctl(name, "", bufSz)
		if inactive {
			io.Flags |= DMStatusTableFlag
		}
		if err := c.rawIoctl(cmdDMTableStatus, unsafe.Pointer(io)); err != nil {
			// If buffer too small, try again with larger size.
			if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EINVAL) {
				bufSz *= 2
				continue
			}
			return "", fmt.Errorf("dm table status '%s': %w", name, err)
		}
		// Parse status strings from payload: [dm_target_spec][status-string+NUL][pad] ...
		headerSize := int(unsafe.Sizeof(dmIoctl{}))
		i := headerSize
		end := int(io.DataSize)
		if end == 0 || end > len(buf) {
			end = len(buf)
		}
		var out []byte
		first := true
		for i+int(unsafe.Sizeof(dmTargetSpec{})) <= end {
			spec := (*dmTargetSpec)(unsafe.Pointer(&buf[i]))
			i += int(unsafe.Sizeof(dmTargetSpec{}))
			// read NUL-terminated string starting at i
			j := i
			for j < end && buf[j] != 0 {
				j++
			}
			if !first {
				out = append(out, '\n')
			}
			first = false
			out = append(out, buf[i:j]...)
			// advance to 8-byte boundary from start of spec
			rel := j - (i - int(unsafe.Sizeof(dmTargetSpec{}))) + 1 // include NUL
			pad := ((rel + 7) &^ 7) - rel
			i = j + 1 + pad
			if spec.Next == 0 {
				break
			}
		}
		return string(out), nil
	}
	return "", fmt.Errorf("dm table status '%s': insufficient buffer after retries", name)
}
