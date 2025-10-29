//go:build linux

package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"unsafe"

	dm "github.com/ChengyuZhu6/veritysetup-go/pkg/dm"
	verity "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
	"golang.org/x/sys/unix"
)

// parseOpenArgs parses flags for the open subcommand.
// Usage: open [options] <data_device> <name> <hash_device> <root_hash>
func parseOpenArgs(args []string) (*verity.VerityParams, string, string, string, []byte, []string, error) {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	hashName := fs.String("hash", "sha256", "hash algorithm")
	dataBlockSize := fs.Uint("data-block-size", 4096, "data block size in bytes")
	hashBlockSize := fs.Uint("hash-block-size", 4096, "hash block size in bytes")
	saltHex := fs.String("salt", "", "salt as hex string or '-' for none")
	dataBlocks := fs.Uint64("data-blocks", 0, "number of data blocks (override file size)")
	noSuper := fs.Bool("no-superblock", false, "hash device has no superblock")
	hashOffset := fs.Uint64("hash-offset", 0, "hash area offset when no superblock")

	if err := fs.Parse(args); err != nil {
		return nil, "", "", "", nil, nil, err
	}
	rest := fs.Args()
	if len(rest) < 4 {
		return nil, "", "", "", nil, nil, errors.New("require <data_device> <name> <hash_device> <root_hash>")
	}
	dataDev := rest[0]
	name := rest[1]
	hashDev := rest[2]
	rootHex := rest[3]

	p := verity.DefaultVerityParams()
	p.HashName = strings.ToLower(*hashName)
	p.DataBlockSize = uint32(*dataBlockSize)
	p.HashBlockSize = uint32(*hashBlockSize)
	p.NoSuperblock = *noSuper
	p.HashAreaOffset = *hashOffset

	if !verity.IsBlockSizeValid(p.DataBlockSize) {
		return nil, "", "", "", nil, nil, fmt.Errorf("invalid data block size: %d", p.DataBlockSize)
	}
	if !verity.IsBlockSizeValid(p.HashBlockSize) {
		return nil, "", "", "", nil, nil, fmt.Errorf("invalid hash block size: %d", p.HashBlockSize)
	}
	if p.NoSuperblock && (p.HashAreaOffset%uint64(p.HashBlockSize) != 0) {
		return nil, "", "", "", nil, nil, fmt.Errorf("hash offset %d must be aligned to hash block size %d", p.HashAreaOffset, p.HashBlockSize)
	}

	if *saltHex != "" && *saltHex != "-" {
		b := make([]byte, hex.DecodedLen(len(*saltHex)))
		n, err := hex.Decode(b, []byte(*saltHex))
		if err != nil {
			return nil, "", "", "", nil, nil, fmt.Errorf("invalid salt hex: %w", err)
		}
		p.Salt = b[:n]
		if len(p.Salt) > int(verity.MaxSaltSize) {
			return nil, "", "", "", nil, nil, fmt.Errorf("salt too large: %d > %d", len(p.Salt), verity.MaxSaltSize)
		}
		p.SaltSize = uint16(len(p.Salt))
	} else {
		p.Salt = nil
		p.SaltSize = 0
	}

	if *dataBlocks != 0 {
		p.DataBlocks = *dataBlocks
	} else if *noSuper {
		// Only derive data blocks here if no-superblock mode is requested.
		// For superblock mode, parameters (including DataBlocks) will be adopted from the superblock later.
		size, err := getBlockOrFileSize(dataDev)
		if err != nil {
			return nil, "", "", "", nil, nil, fmt.Errorf("determine data device size: %w", err)
		}
		if size%int64(p.DataBlockSize) != 0 {
			return nil, "", "", "", nil, nil, fmt.Errorf("data size %d not multiple of data block size %d", size, p.DataBlockSize)
		}
		p.DataBlocks = uint64(size / int64(p.DataBlockSize))
	}

	// Parse root hash
	rootBytes := make([]byte, hex.DecodedLen(len(rootHex)))
	nRoot, err := hex.Decode(rootBytes, []byte(strings.TrimSpace(rootHex)))
	if err != nil {
		return nil, "", "", "", nil, nil, fmt.Errorf("invalid root hex: %w", err)
	}
	rootBytes = rootBytes[:nRoot]

	// Build flags
	var flags []string

	return &p, dataDev, name, hashDev, rootBytes, flags, nil
}

func runOpen(p *verity.VerityParams, dataDev, name, hashDev string, rootDigest []byte, flags []string) error {
	// If superblock is present, read and adopt; otherwise require valid hash offset
	if !p.NoSuperblock {
		f, err := os.OpenFile(hashDev, os.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("open hash device: %w", err)
		}
		defer f.Close()
		buf := make([]byte, verity.VeritySuperblockSize)
		if _, err := f.ReadAt(buf, 0); err != nil {
			return fmt.Errorf("read superblock: %w", err)
		}
		sb, err := verity.DeserializeSuperblock(buf)
		if err != nil {
			return err
		}
		if err := verity.AdoptParamsFromSuperblock(p, sb); err != nil {
			return err
		}
	} else {
		if p.HashAreaOffset%uint64(p.HashBlockSize) != 0 {
			return fmt.Errorf("hash offset %d must be aligned to hash block size %d", p.HashAreaOffset, p.HashBlockSize)
		}
	}

	// Assemble dm-verity params (pass device paths; dm will print major:minor in table)
	a := dm.OpenArgs{
		Version:        1,
		DataDevice:     dataDev,
		HashDevice:     hashDev,
		DataBlockSize:  p.DataBlockSize,
		HashBlockSize:  p.HashBlockSize,
		DataBlocks:     p.DataBlocks,
		HashName:       p.HashName,
		RootDigest:     rootDigest,
		Salt:           p.Salt,
		HashStartBytes: p.HashAreaOffset,
		Flags:          flags,
	}
	params, err := dm.BuildTargetParams(a)
	if err != nil {
		return err
	}

	// Length is in 512-byte sectors
	lengthSectors := uint64(p.DataBlocks) * uint64(p.DataBlockSize/512)

	c, err := dm.Open()
	if err != nil {
		return err
	}
	defer c.Close()

	created := false
	defer func() {
		if !created {
			_ = c.RemoveDevice(name)
		}
	}()

	if _, err := c.CreateDevice(name); err != nil {
		return err
	}

	tgt := dm.Target{SectorStart: 0, Length: lengthSectors, Type: "verity", Params: params}
	fmt.Fprintf(os.Stderr, "params: %q\n", params)
	if err := c.LoadTable(name, []dm.Target{tgt}); err != nil {
		_ = c.RemoveDevice(name)
		return err
	}
	if err := c.SuspendDevice(name, false); err != nil { // resume to activate
		_ = c.RemoveDevice(name)
		return err
	}
	created = true

	// Wait for /dev/mapper/<name>
	devPath := "/dev/mapper/" + name
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(devPath); err == nil {
			fmt.Printf("%s\n", devPath)
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	// If still not present, return path anyway; udev may be absent
	fmt.Printf("%s\n", devPath)
	return nil
}

// getBlockOrFileSize returns the size in bytes of a regular file or a block device.
// For block devices, it uses BLKGETSIZE64 to obtain the size.
func getBlockOrFileSize(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	mode := st.Mode()
	if (mode&os.ModeDevice) != 0 && (mode&os.ModeCharDevice) == 0 {
		// Block device: use BLKGETSIZE64
		f, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		var size uint64
		// #nosec G103 - IOCTL call with pointer is intentional
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
		if errno != 0 {
			return 0, errno
		}
		return int64(size), nil
	}
	// Regular file or other: rely on st.Size()
	return st.Size(), nil
}
