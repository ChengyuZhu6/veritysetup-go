package dm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func requireDMIntegrationEnv(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/dev/mapper/control"); err != nil {
		t.Skip("/dev/mapper/control not available")
	}
	if unix.Geteuid() != 0 {
		t.Skip("requires root")
	}
}

func TestDMOpenControl(t *testing.T) {
	requireDMIntegrationEnv(t)
	c, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = c.Close()
}

func TestDMCreateDevice(t *testing.T) {
	requireDMIntegrationEnv(t)

	c, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	var rb [8]byte
	_, _ = rand.Read(rb[:])
	name := "dmtest-" + hex.EncodeToString(rb[:])
	_, err = c.CreateDevice(name)
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	defer func() { _ = c.RemoveDevice(name) }()

	target := pickAvailableTarget(t)
	tgts := []Target{{
		SectorStart: 0,
		Length:      2048,
		Type:        target,
		Params:      "",
	}}
	if err := c.LoadTable(name, tgts); err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if err := c.SuspendDevice(name, false); err != nil {
		t.Fatalf("Resume: %v", err)
	}

	if _, err := c.TableStatus(name, false); err != nil {
		t.Fatalf("TableStatus: %v", err)
	}

	if err := c.LoadTable(name, tgts); err != nil {
		t.Fatalf("Reload (create inactive): %v", err)
	}
	if err := c.ClearTable(name); err != nil {
		t.Fatalf("ClearTable (inactive): %v", err)
	}

	if err := c.SuspendDevice(name, true); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if err := c.RemoveDevice(name); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
}

func TestDMSuspendNoFlush(t *testing.T) {
	requireDMIntegrationEnv(t)

	c, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	var rb [8]byte
	_, _ = rand.Read(rb[:])
	name := "dmtest-noflush-" + hex.EncodeToString(rb[:])
	if _, err := c.CreateDevice(name); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	defer func() { _ = c.RemoveDevice(name) }()

	tgts := []Target{{SectorStart: 0, Length: 8, Type: pickAvailableTarget(t), Params: ""}}
	if err := c.LoadTable(name, tgts); err != nil {
		t.Fatalf("LoadTable: %v", err)
	}

	if err := c.SuspendDevice(name, false); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if err := c.RemoveDevice(name); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
}

func TestDMCreateRemove(t *testing.T) {
	requireDMIntegrationEnv(t)
	c, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	name := "dmtest-crem-" + hex.EncodeToString(rb[:])
	if _, err := c.CreateDevice(name); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if err := c.RemoveDevice(name); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
}

func TestDMLoadTable(t *testing.T) {
	requireDMIntegrationEnv(t)
	c, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	name := "dmtest-load-" + hex.EncodeToString(rb[:])
	if _, err := c.CreateDevice(name); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	defer func() { _ = c.RemoveDevice(name) }()
	tgts := []Target{{SectorStart: 0, Length: 8, Type: pickAvailableTarget(t), Params: ""}}
	if err := c.LoadTable(name, tgts); err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if err := c.RemoveDevice(name); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
}

func TestDMSuspendResume(t *testing.T) {
	requireDMIntegrationEnv(t)
	c, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	name := "dmtest-susres-" + hex.EncodeToString(rb[:])
	if _, err := c.CreateDevice(name); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	defer func() { _ = c.RemoveDevice(name) }()
	tgts := []Target{{SectorStart: 0, Length: 8, Type: pickAvailableTarget(t), Params: ""}}
	if err := c.LoadTable(name, tgts); err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if err := c.SuspendDevice(name, false); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if err := c.SuspendDevice(name, true); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if err := c.RemoveDevice(name); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
}

func TestDMTableStatus(t *testing.T) {
	requireDMIntegrationEnv(t)
	c, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	name := "dmtest-status-" + hex.EncodeToString(rb[:])
	if _, err := c.CreateDevice(name); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	defer func() { _ = c.RemoveDevice(name) }()
	tgts := []Target{{SectorStart: 0, Length: 8, Type: pickAvailableTarget(t), Params: ""}}
	if err := c.LoadTable(name, tgts); err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if err := c.SuspendDevice(name, false); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if _, err := c.TableStatus(name, false); err != nil {
		t.Fatalf("TableStatus: %v", err)
	}
	if err := c.SuspendDevice(name, true); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if err := c.RemoveDevice(name); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
}

func TestDMClearTable(t *testing.T) {
	requireDMIntegrationEnv(t)
	c, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	name := "dmtest-clear-" + hex.EncodeToString(rb[:])
	if _, err := c.CreateDevice(name); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	defer func() { _ = c.RemoveDevice(name) }()
	tgts := []Target{{SectorStart: 0, Length: 8, Type: pickAvailableTarget(t), Params: ""}}
	if err := c.LoadTable(name, tgts); err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if err := c.SuspendDevice(name, false); err != nil {
		t.Fatalf("Resume: %v", err)
	}

	if err := c.LoadTable(name, tgts); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if err := c.ClearTable(name); err != nil {
		if !errors.Is(err, unix.EINVAL) {
			t.Fatalf("ClearTable: %v", err)
		}
	}
	if err := c.SuspendDevice(name, true); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if err := c.RemoveDevice(name); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
}

func TestDMOpenCloseLoop(t *testing.T) {
	requireDMIntegrationEnv(t)
	for i := 0; i < 5; i++ {
		c, err := Open()
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
}

func pickAvailableTarget(t *testing.T) string {
	t.Helper()
	if hasDMTarget(t, "error") || hasSysfsModule("dm_error") {
		return "error"
	}
	return "error"
}

func hasDMTarget(t *testing.T, name string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2_000_000_000)
	defer cancel()
	cmd := exec.CommandContext(ctx, "dmsetup", "targets")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return containsWord(string(out), name)
}

func hasSysfsModule(name string) bool {
	if _, err := os.Stat("/sys/module/" + name); err == nil {
		return true
	}
	return false
}

func containsWord(s, w string) bool {
	return len(s) >= len(w) && (s == w || (len(s) > len(w) && (contains(s, "\n"+w+" ") || contains(s, " "+w+" ") || contains(s, "\n"+w+"\n") || contains(s, " "+w+"\n"))))
}

func contains(s, sub string) bool {
	return (len(sub) == 0) || (len(s) >= len(sub) && (indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	n, m := len(s), len(sub)
	if m == 0 {
		return 0
	}
	if m > n {
		return -1
	}
	for i := 0; i <= n-m; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
}
