package verity

const (
	VeritySignature      = "verity\x00\x00"
	VeritySuperblockSize = 512
	VerityMaxHashType    = 1
	VerityMaxLevels      = 63
	MaxSaltSize          = 256
)

// VeritySuperblock represents the on-disk superblock format
type VeritySuperblock struct {
	Signature     [8]byte   `binary:"big"`    // "verity\0\0"
	Version       uint32    `binary:"little"` // superblock version
	HashType      uint32    `binary:"little"` // 0 - Chrome OS, 1 - normal
	UUID          [16]byte  `binary:"big"`    // UUID of hash device
	Algorithm     [32]byte  `binary:"big"`    // hash algorithm name
	DataBlockSize uint32    `binary:"little"` // data block in bytes
	HashBlockSize uint32    `binary:"little"` // hash block in bytes
	DataBlocks    uint64    `binary:"little"` // number of data blocks
	SaltSize      uint16    `binary:"little"` // salt size
	Pad1          [6]byte   `binary:"big"`
	Salt          [256]byte `binary:"big"` // salt
	Pad2          [168]byte `binary:"big"`
}

// VerityParams contains parameters for verity volume
type VerityParams struct {
	HashName       string
	DataBlockSize  uint32
	HashBlockSize  uint32
	DataSize       uint64
	HashType       uint32
	Salt           []byte
	SaltSize       uint16
	HashAreaOffset uint64
	Flags          uint32
}

// IsBlockSizeValid checks if block size is valid
func IsBlockSizeValid(size uint32) bool {
	return size%512 == 0 && size >= 512 && size <= (512*1024) && (size&(size-1)) == 0
}
