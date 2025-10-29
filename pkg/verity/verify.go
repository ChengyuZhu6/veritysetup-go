package verity

import (
	"os"
)

// Verifier implements user-space verification against the stored hash tree and root digest.
type Verifier struct {
	vh       *VerityHash
	dataFile *os.File
	hashFile *os.File
}

// NewVerifier constructs a Verifier for the given devices and root digest.
func NewVerifier(params *VerityParams, dataPath, hashPath string, rootDigest []byte) (*Verifier, error) {
	vh := NewVerityHash(params, dataPath, hashPath, rootDigest)
	dataFile, hashFile, err := vh.openDeviceFiles(true)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		vh:       vh,
		dataFile: dataFile,
		hashFile: hashFile,
	}, nil
}

// Close closes any open file descriptors associated with the Verifier.
func (v *Verifier) Close() error {
	var first error
	if v.dataFile != nil {
		if err := v.dataFile.Close(); err != nil {
			first = err
		}
	}
	if v.hashFile != nil {
		if err := v.hashFile.Close(); err != nil {
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// VerifyAll verifies the entire data range against the hash tree and root.
func (v *Verifier) VerifyAll() error {
	return v.vh.Verify()
}
