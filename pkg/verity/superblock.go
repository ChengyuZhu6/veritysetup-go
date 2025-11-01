package verity

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/google/uuid"
)

const (
	VeritySignature      = "verity\x00\x00"
	VeritySuperblockSize = 512
	VerityMaxHashType    = 1
	VerityMaxLevels      = 63
	VerityMaxDigestSize  = 1024
	MaxSaltSize          = 256
	diskSectorSize       = 512
)

var (
	errInvalidSignature = errors.New("verity: invalid superblock signature")
	errInvalidVersion   = errors.New("verity: unsupported superblock version")
)

func init() {
	if binary.Size(VeritySuperblock{}) != VeritySuperblockSize {
		panic(fmt.Sprintf("verity: unexpected superblock size: %d", binary.Size(VeritySuperblock{})))
	}
}

func alignUp(value, alignment uint64) uint64 {
	if alignment == 0 {
		return value
	}
	rem := value % alignment
	if rem == 0 {
		return value
	}
	return value + (alignment - rem)
}

type VeritySuperblock struct {
	Signature     [8]byte
	Version       uint32
	HashType      uint32
	UUID          [16]byte
	Algorithm     [32]byte
	DataBlockSize uint32
	HashBlockSize uint32
	DataBlocks    uint64
	SaltSize      uint16
	Pad1          [6]byte
	Salt          [256]byte
	Pad2          [168]byte
}

func DefaultVeritySuperblock() VeritySuperblock {
	return VeritySuperblock{
		Signature:     [8]byte{0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x00, 0x00},
		Version:       1,
		HashType:      1,
		DataBlockSize: 4096,
		HashBlockSize: 4096,
		Algorithm:     [32]byte{0x73, 0x68, 0x61, 0x32, 0x35, 0x36},
	}
}

func NewSuperblock() *VeritySuperblock {
	sb := DefaultVeritySuperblock()
	return &sb
}

func (sb *VeritySuperblock) Serialize() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, VeritySuperblockSize))
	if err := binary.Write(buf, binary.LittleEndian, sb); err != nil {
		return nil, fmt.Errorf("verity: failed to serialize superblock: %w", err)
	}
	if buf.Len() != VeritySuperblockSize {
		return nil, fmt.Errorf("verity: serialized superblock has unexpected length %d", buf.Len())
	}
	return buf.Bytes(), nil
}

func DeserializeSuperblock(data []byte) (*VeritySuperblock, error) {
	if len(data) < VeritySuperblockSize {
		return nil, fmt.Errorf("verity: data too short for superblock (%d bytes)", len(data))
	}

	sb := &VeritySuperblock{}
	buf := bytes.NewReader(data[:VeritySuperblockSize])
	if err := binary.Read(buf, binary.LittleEndian, sb); err != nil {
		return nil, fmt.Errorf("verity: failed to deserialize superblock: %w", err)
	}

	if err := sb.validateBasic(); err != nil {
		return nil, err
	}
	return sb, nil
}

func ReadSuperblock(r io.ReaderAt, sbOffset uint64) (*VeritySuperblock, error) {
	if sbOffset%diskSectorSize != 0 {
		return nil, fmt.Errorf("verity: superblock offset %d is not %d-byte aligned", sbOffset, diskSectorSize)
	}
	if sbOffset > math.MaxInt64 {
		return nil, fmt.Errorf("verity: superblock offset overflows int64: %d", sbOffset)
	}

	buf := make([]byte, VeritySuperblockSize)
	n, err := r.ReadAt(buf, int64(sbOffset))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("verity: read superblock failed: %w", err)
	}
	if n != VeritySuperblockSize {
		return nil, fmt.Errorf("verity: short read for superblock: got %d bytes", n)
	}

	sb, err := DeserializeSuperblock(buf)
	if err != nil {
		return nil, err
	}

	if uuidVal, uuidErr := uuid.FromBytes(sb.UUID[:]); uuidErr == nil {
		if uuidVal == uuid.Nil {
			return nil, errors.New("verity: superblock missing UUID")
		}
	}

	return sb, nil
}

func (sb *VeritySuperblock) WriteSuperblock(w io.WriterAt, sbOffset uint64) error {
	if sbOffset%diskSectorSize != 0 {
		return fmt.Errorf("verity: superblock offset %d is not %d-byte aligned", sbOffset, diskSectorSize)
	}
	if sbOffset > math.MaxInt64 {
		return fmt.Errorf("verity: superblock offset overflows int64: %d", sbOffset)
	}

	data, err := sb.Serialize()
	if err != nil {
		return err
	}

	n, writeErr := w.WriteAt(data, int64(sbOffset))
	if writeErr != nil {
		return fmt.Errorf("verity: write superblock failed: %w", writeErr)
	}
	if n != len(data) {
		return fmt.Errorf("verity: short write for superblock: wrote %d bytes", n)
	}
	return nil
}

func (sb *VeritySuperblock) validateBasic() error {
	if string(sb.Signature[:]) != VeritySignature {
		return errInvalidSignature
	}
	if sb.Version != 1 {
		return fmt.Errorf("%w: %d", errInvalidVersion, sb.Version)
	}
	return nil
}

func (sb *VeritySuperblock) algorithmString() string {
	return strings.ToLower(strings.TrimRight(string(sb.Algorithm[:]), "\x00"))
}

func (sb *VeritySuperblock) UUIDString() (string, error) {
	uuidVal, err := uuid.FromBytes(sb.UUID[:])
	if err != nil {
		return "", fmt.Errorf("verity: invalid superblock UUID: %w", err)
	}
	if uuidVal == uuid.Nil {
		return "", errors.New("verity: superblock missing UUID")
	}
	return uuidVal.String(), nil
}

func (sb *VeritySuperblock) SetUUIDFromString(s string) error {
	uuidVal, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("verity: invalid UUID %q: %w", s, err)
	}
	copy(sb.UUID[:], uuidVal[:])
	return nil
}

func BuildSuperblockFromParams(p *VerityParams) (*VeritySuperblock, error) {
	return buildSuperblockFromParams(p)
}

func buildSuperblockFromParams(p *VerityParams) (*VeritySuperblock, error) {
	if p == nil {
		return nil, errors.New("verity: nil params provided")
	}
	if !IsBlockSizeValid(p.DataBlockSize) || !IsBlockSizeValid(p.HashBlockSize) {
		return nil, fmt.Errorf("verity: invalid block sizes: data %d hash %d", p.DataBlockSize, p.HashBlockSize)
	}
	if p.HashType > VerityMaxHashType {
		return nil, fmt.Errorf("verity: unsupported hash type %d", p.HashType)
	}
	if len(p.Salt) != int(p.SaltSize) {
		return nil, fmt.Errorf("verity: salt size mismatch: declared %d actual %d", p.SaltSize, len(p.Salt))
	}
	if p.SaltSize > MaxSaltSize {
		return nil, fmt.Errorf("verity: salt too large: %d > %d", p.SaltSize, MaxSaltSize)
	}

	algo := strings.ToLower(strings.TrimSpace(p.HashName))
	if algo == "" {
		return nil, errors.New("verity: hash algorithm required")
	}
	if !isHashAlgorithmSupported(algo) {
		return nil, fmt.Errorf("verity: hash algorithm %s not supported", algo)
	}

	sb := DefaultVeritySuperblock()
	copy(sb.Signature[:], VeritySignature)
	sb.Version = 1
	sb.HashType = p.HashType
	sb.DataBlockSize = p.DataBlockSize
	sb.HashBlockSize = p.HashBlockSize
	sb.DataBlocks = p.DataBlocks
	sb.SaltSize = p.SaltSize
	sb.UUID = p.UUID

	for i := range sb.Algorithm {
		sb.Algorithm[i] = 0
	}
	copy(sb.Algorithm[:], []byte(algo))

	for i := range sb.Salt {
		sb.Salt[i] = 0
	}
	copy(sb.Salt[:], p.Salt)

	p.NoSuperblock = false

	return &sb, nil
}

func adoptParamsFromSuperblock(p *VerityParams, sb *VeritySuperblock, sbOffset uint64) error {
	if p == nil || sb == nil {
		return errors.New("verity: nil params or superblock")
	}
	if err := sb.validateBasic(); err != nil {
		return err
	}
	if sb.HashType > VerityMaxHashType {
		return fmt.Errorf("verity: unsupported hash type %d", sb.HashType)
	}
	if !IsBlockSizeValid(sb.DataBlockSize) || !IsBlockSizeValid(sb.HashBlockSize) {
		return fmt.Errorf("verity: invalid block size in superblock: data %d hash %d", sb.DataBlockSize, sb.HashBlockSize)
	}
	if sb.SaltSize > MaxSaltSize {
		return fmt.Errorf("verity: superblock salt too large: %d", sb.SaltSize)
	}

	algo := sb.algorithmString()
	if algo == "" {
		return fmt.Errorf("verity: missing hash algorithm in superblock")
	}

	if p.HashName == "" {
		p.HashName = algo
	} else if strings.ToLower(p.HashName) != algo {
		return fmt.Errorf("verity: algorithm mismatch: param %s superblock %s", p.HashName, algo)
	}

	if !isHashAlgorithmSupported(p.HashName) {
		return fmt.Errorf("verity: hash algorithm %s not supported", p.HashName)
	}

	if p.DataBlockSize == 0 {
		p.DataBlockSize = sb.DataBlockSize
	} else if p.DataBlockSize != sb.DataBlockSize {
		return fmt.Errorf("verity: data block size mismatch: param %d sb %d", p.DataBlockSize, sb.DataBlockSize)
	}

	if p.HashBlockSize == 0 {
		p.HashBlockSize = sb.HashBlockSize
	} else if p.HashBlockSize != sb.HashBlockSize {
		return fmt.Errorf("verity: hash block size mismatch: param %d sb %d", p.HashBlockSize, sb.HashBlockSize)
	}

	if p.DataBlocks == 0 {
		p.DataBlocks = sb.DataBlocks
	} else if p.DataBlocks != sb.DataBlocks {
		return fmt.Errorf("verity: data blocks mismatch: param %d sb %d", p.DataBlocks, sb.DataBlocks)
	}

	if len(p.Salt) == 0 {
		p.Salt = make([]byte, sb.SaltSize)
		copy(p.Salt, sb.Salt[:sb.SaltSize])
		p.SaltSize = sb.SaltSize
	} else {
		if p.SaltSize != sb.SaltSize || !bytes.Equal(p.Salt, sb.Salt[:sb.SaltSize]) {
			return fmt.Errorf("verity: salt mismatch")
		}
	}

	p.HashType = sb.HashType
	if p.UUID == ([16]byte{}) {
		p.UUID = sb.UUID
	} else if p.UUID != sb.UUID {
		return fmt.Errorf("verity: UUID mismatch")
	}
	p.NoSuperblock = false
	p.HashAreaOffset = sbOffset
	return nil
}

func AdoptParamsFromSuperblock(p *VerityParams, sb *VeritySuperblock, sbOffset uint64) error {
	return adoptParamsFromSuperblock(p, sb, sbOffset)
}

func isHashAlgorithmSupported(name string) bool {
	h := map[string]crypto.Hash{
		"sha1":   crypto.SHA1,
		"sha256": crypto.SHA256,
		"sha512": crypto.SHA512,
	}
	algo := strings.ToLower(strings.TrimSpace(name))
	hash, ok := h[algo]
	if !ok {
		return false
	}
	return hash.Available()
}
