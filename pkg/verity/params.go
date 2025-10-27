package verity

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

func IsBlockSizeValid(size uint32) bool {
	return size%512 == 0 && size >= 512 && size <= (512*1024) && (size&(size-1)) == 0
}
