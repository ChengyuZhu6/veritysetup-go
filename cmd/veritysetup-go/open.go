package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	dm "github.com/ChengyuZhu6/veritysetup-go/pkg/dm"
	"github.com/ChengyuZhu6/veritysetup-go/pkg/keyring"
	"github.com/ChengyuZhu6/veritysetup-go/pkg/utils"
	verity "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
)

func parseOpenArgs(args []string) (*verity.VerityParams, string, string, string, []byte, []string, string, error) {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	flags := defaultFlags(fs)

	if err := fs.Parse(args); err != nil {
		return nil, "", "", "", nil, nil, "", err
	}

	rest := fs.Args()
	if len(rest) < 4 {
		return nil, "", "", "", nil, nil, "", errors.New("require <data_device> <name> <hash_device> <root_hash>")
	}
	dataDev := rest[0]
	name := rest[1]
	hashDev := rest[2]
	rootHex := rest[3]

	if strings.TrimSpace(name) == "" {
		return nil, "", "", "", nil, nil, "", fmt.Errorf("device name is required")
	}
	if strings.Contains(name, "/") {
		return nil, "", "", "", nil, nil, "", fmt.Errorf("device name must not contain '/' characters")
	}
	if len(name) >= dm.DMNameLen {
		return nil, "", "", "", nil, nil, "", fmt.Errorf("device name too long (max %d characters)", dm.DMNameLen-1)
	}

	p := verity.DefaultVerityParams()

	applyFlags(&p, flags)

	if !*flags.NoSuper {
		p.HashName = ""
		p.DataBlockSize = 0
		p.HashBlockSize = 0
	}

	if err := validateAndApplyBlockSizes(&p, flags); err != nil {
		return nil, "", "", "", nil, nil, "", err
	}

	if err := utils.ValidateHashOffset(p.HashAreaOffset, p.HashBlockSize, p.NoSuperblock); err != nil {
		return nil, "", "", "", nil, nil, "", err
	}

	salt, saltSize, err := utils.ApplySalt(*flags.SaltHex, int(verity.MaxSaltSize))
	if err != nil {
		return nil, "", "", "", nil, nil, "", err
	}
	p.Salt = salt
	p.SaltSize = saltSize

	if *flags.NoSuper {
		dataBlocks, err := utils.CalculateDataBlocks(dataDev, *flags.DataBlocks, p.DataBlockSize)
		if err != nil {
			return nil, "", "", "", nil, nil, "", err
		}
		p.DataBlocks = dataBlocks
	}

	rootBytes, err := utils.ParseRootHash(rootHex)
	if err != nil {
		return nil, "", "", "", nil, nil, "", err
	}

	var dmFlags []string
	signatureFile := *flags.RootHashSig
	return &p, dataDev, name, hashDev, rootBytes, dmFlags, signatureFile, nil
}

func runOpen(p *verity.VerityParams, dataDev, name, hashDev string, rootDigest []byte, flags []string, signatureFile string) error {
	var keyID keyring.KeySerial
	var keyDesc string

	if signatureFile != "" {
		if err := keyring.CheckKeyringSupport(); err != nil {
			return fmt.Errorf("signature verification requires kernel keyring support: %w", err)
		}

		if err := dm.CheckVeritySignatureSupport(); err != nil {
			return fmt.Errorf("failed to check dm-verity signature support: %w", err)
		}
	}

	dataLoop, cleanup, err := utils.SetupLoopDevice(dataDev)
	if err != nil {
		return fmt.Errorf("setup data loop device: %w", err)
	}
	defer func() {
		if dataLoop != dataDev {
			cleanup()
		}
	}()

	hashLoop, cleanup, err := utils.SetupLoopDevice(hashDev)
	if err != nil {
		return fmt.Errorf("setup hash loop device: %w", err)
	}
	defer func() {
		if hashLoop != hashDev {
			cleanup()
		}
	}()

	if err := verity.InitParams(p, dataLoop, hashLoop); err != nil {
		return fmt.Errorf("InitParams failed: %w", err)
	}

	if err := utils.ValidateRootHashSize(rootDigest, p.HashName); err != nil {
		return err
	}

	if signatureFile != "" {
		signatureData, err := os.ReadFile(signatureFile)
		if err != nil {
			return fmt.Errorf("failed to read signature file: %w", err)
		}

		uuidStr := ""
		if p.UUID != ([16]byte{}) {
			uuidStr = fmt.Sprintf("%x-%x-%x-%x-%x",
				p.UUID[0:4], p.UUID[4:6], p.UUID[6:8],
				p.UUID[8:10], p.UUID[10:16])
		}

		if uuidStr != "" {
			keyDesc = fmt.Sprintf("cryptsetup:%s-%s", uuidStr, name)
		} else {
			keyDesc = fmt.Sprintf("cryptsetup:%s", name)
		}

		keyID, err = keyring.AddKeyToThreadKeyring("user", keyDesc, signatureData)
		if err != nil {
			return fmt.Errorf("failed to load signature into keyring: %w", err)
		}

		log.Printf("Loaded signature into thread keyring (key ID: %d, description: %s)\n", keyID, keyDesc)

		defer func() {
			if err := keyring.UnlinkKeyFromThreadKeyring(keyID); err != nil {
				log.Printf("Warning: failed to unlink key from keyring: %v", err)
			}
		}()
	}

	a := dm.OpenArgs{
		Version:            p.HashType,
		DataDevice:         dataLoop,
		HashDevice:         hashLoop,
		DataBlockSize:      p.DataBlockSize,
		HashBlockSize:      p.HashBlockSize,
		DataBlocks:         p.DataBlocks,
		HashName:           p.HashName,
		RootDigest:         rootDigest,
		Salt:               p.Salt,
		HashStartBytes:     p.HashAreaOffset,
		Flags:              flags,
		RootHashSigKeyDesc: keyDesc,
	}
	params, err := dm.BuildTargetParams(a)
	if err != nil {
		return err
	}

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
	if err := c.LoadTable(name, []dm.Target{tgt}); err != nil {
		_ = c.RemoveDevice(name)
		return fmt.Errorf("load table: %w", err)
	}
	if err := c.SuspendDevice(name, false); err != nil {
		_ = c.RemoveDevice(name)
		if signatureFile != "" && errors.Is(err, unix.EKEYREJECTED) {
			return fmt.Errorf("signature verification failed: key rejected by kernel")
		}
		return fmt.Errorf("resume device: %w", err)
	}
	created = true

	devPath := "/dev/mapper/" + name
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(devPath); err == nil {
			fmt.Printf("%s\n", devPath)
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Printf("%s\n", devPath)
	return nil
}
