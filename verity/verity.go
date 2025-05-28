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

// DefaultDmverityOptions returns a DmverityOptions struct with default values
func DefaultVeritySuperblock() VeritySuperblock {
	return VeritySuperblock{
		Signature:     [8]byte{0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x00, 0x00},
		Version:       1,
		HashType:      1,
		DataBlockSize: 4096,
		HashBlockSize: 4096,
		Algorithm:     [32]byte{0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
}

// VerityParams contains parameters for verity volume
type VerityParams struct {
	HashName       string
	DataBlockSize  uint32
	HashBlockSize  uint32
	DataBlocks     uint64
	HashType       uint32
	Salt           []byte
	SaltSize       uint16
	HashAreaOffset uint64
	NoSuperblock   bool
}

func DefaultVerityParams() VerityParams {
	return VerityParams{
		HashName:      "sha256",
		DataBlockSize: 4096,
		HashBlockSize: 4096,
		HashType:      1,
		NoSuperblock:  false,
	}
}

// IsBlockSizeValid checks if block size is valid
func IsBlockSizeValid(size uint32) bool {
	return size%512 == 0 && size >= 512 && size <= (512*1024) && (size&(size-1)) == 0
}
