package verity

const (
	VeritySignature   = "verity\x00\x00"
	VerityMaxHashType = 1
	VerityMaxLevels   = 63
)

// VeritySuperblock represents the on-disk superblock format
type VeritySuperblock struct {
	Signature     [8]byte  // "verity\0\0"
	Version       uint32   // superblock version
	HashType      uint32   // 0 - Chrome OS, 1 - normal
	UUID          [16]byte // UUID of hash device
	Algorithm     [32]byte // hash algorithm name
	DataBlockSize uint32   // data block in bytes
	HashBlockSize uint32   // hash block in bytes
	DataBlocks    uint64   // number of data blocks
	SaltSize      uint16   // salt size
	_pad1         [6]byte
	Salt          [256]byte // salt
	_pad2         [168]byte
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
