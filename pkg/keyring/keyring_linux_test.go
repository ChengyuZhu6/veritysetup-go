package keyring

import (
	"testing"
)

func TestAddAndUnlinkKey(t *testing.T) {
	if err := CheckKeyringSupport(); err != nil {
		t.Skipf("Keyring not supported: %v", err)
	}

	payload := []byte("test-payload")
	keyID, err := AddKeyToThreadKeyring("user", "test-key", payload)
	if err != nil {
		t.Fatalf("Failed to add key: %v", err)
	}

	if keyID == 0 {
		t.Fatal("Expected non-zero key ID")
	}

	err = UnlinkKeyFromThreadKeyring(keyID)
	if err != nil {
		t.Fatalf("Failed to unlink key: %v", err)
	}
}
