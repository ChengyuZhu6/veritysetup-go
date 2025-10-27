package verity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

func SetupTestData(dataPath, hashPath string, p *VerityParams, dataSize uint64) error {
	if err := GenerateRandomFile(dataPath, dataSize); err != nil {
		return fmt.Errorf("failed to generate test data: %w", err)
	}
	if !p.NoSuperblock && p.HashAreaOffset == 0 {
		p.HashAreaOffset = alignUp(VeritySuperblockSize, uint64(p.HashBlockSize))
	}
	vh := NewVerityHash(p, dataPath, hashPath, nil)
	levels, err := vh.calculateHashLevels()
	if err != nil {
		return fmt.Errorf("failed to calculate levels: %w", err)
	}
	var totalTreeBytes uint64
	for i := 0; i < len(levels)-1; i++ {
		totalTreeBytes += levels[i].numBlocks * uint64(p.HashBlockSize)
	}
	totalSize := p.HashAreaOffset + totalTreeBytes
	f, err := os.OpenFile(hashPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create hash file: %w", err)
	}
	defer f.Close()
	if err := f.Truncate(int64(totalSize)); err != nil {
		return fmt.Errorf("failed to preallocate hash file: %w", err)
	}
	return nil
}

func GenerateRandomFile(path string, size uint64) error {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return fmt.Errorf("failed to generate random data: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func SetupVerityTestParams(dataSize uint64) *VerityParams {
	p := DefaultVerityParams()
	p.DataBlocks = dataSize / 4096
	p.Salt = make([]byte, 32)
	p.SaltSize = 32
	return &p
}

func GetVeritySetupRootHash(dataPath string, hashPath string, p *VerityParams) ([]byte, error) {
	cmd := exec.Command("veritysetup", "format",
		dataPath, hashPath+".verity",
		"--hash", p.HashName,
		"--data-block-size", strconv.FormatUint(uint64(p.DataBlockSize), 10),
		"--hash-block-size", strconv.FormatUint(uint64(p.HashBlockSize), 10),
		"--salt", hex.EncodeToString(p.Salt),
		"--uuid", "00000000-0000-0000-0000-000000000000",
	)
	if p.NoSuperblock {
		cmd.Args = append(cmd.Args, "--no-superblock")
	}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("veritysetup failed: %w", err)
	}
	for _, line := range bytes.Split(output, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("Root hash:")) {
			hexHash := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("Root hash:")))
			rootHash := make([]byte, hex.DecodedLen(len(hexHash)))
			if _, err := hex.Decode(rootHash, hexHash); err != nil {
				return nil, fmt.Errorf("failed to decode root hash: %w", err)
			}
			return rootHash, nil
		}
	}
	return nil, fmt.Errorf("root hash not found in veritysetup output")
}

func CorruptFile(path string, offset int64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteAt([]byte{0xFF}, offset)
	return err
}
