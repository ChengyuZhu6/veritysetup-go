package utils

import (
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

func RequireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s not found in PATH", name)
	}
	return p
}

func RequireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatalf("requires root")
	}
}

func RunCmd(t *testing.T, name string, args ...string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, string(out))
	}
	return string(out), string(out)
}

func RunGoCLI(t *testing.T, args ...string) (string, string) {
	t.Helper()
	bin := RequireTool(t, "veritysetup-go")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", bin, args, err, string(out))
	}
	return string(out), string(out)
}

func MakeTempFile(t *testing.T, size int64) string {
	t.Helper()
	f, err := os.CreateTemp("", "vgo-data-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if size > 0 {
		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}
		// Write some random bytes in first block to avoid all-zero special cases
		buf := make([]byte, 4096)
		if _, err := rand.Read(buf); err == nil {
			_, _ = f.WriteSuperblock(buf, 0)
		}
	}
	return f.Name()
}

func SetupLoop(t *testing.T, path string) string {
	t.Helper()
	RequireTool(t, "losetup")
	out, _ := RunCmd(t, "losetup", "-f", "--show", path)
	return FirstLine(out)
}

func DetachLoop(t *testing.T, loop string) {
	t.Helper()
	_, _ = RunCmd(t, "losetup", "-d", loop)
}

func FirstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return s[:i]
		}
	}
	return s
}

func ExtractRootHex(t *testing.T, out string) string {
	t.Helper()
	re := regexp.MustCompile(`(?i)Root hash:\s*([0-9a-f]+)`) // case-insensitive
	m := re.FindStringSubmatch(out)
	if len(m) < 2 {
		t.Fatalf("failed to parse root hash from output: %s", out)
	}
	return m[1]
}

func CreateFormattedFiles(t *testing.T) (dataPath, hashPath, rootHex string) {
	t.Helper()
	dataPath = MakeTempFile(t, 4096*16)
	f, err := os.CreateTemp("", "vgo-hash-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	hashPath = f.Name()
	out, _ := RunGoCLI(t, "format", "--hash", "sha256", "--format", "1", "--data-block-size", "4096", "--hash-block-size", "4096", "--salt", "-", dataPath, hashPath)
	rootHex = ExtractRootHex(t, out)
	return
}

func MaskVerityDevices(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// dmsetup table may output multiple lines; process each line
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		// Expect at least: start len verity version data_dev hash_dev ...
		if len(fields) >= 7 {
			// Find "verity" token to be resilient to optional columns at front
			vIdx := -1
			for idx, tok := range fields {
				if tok == "verity" {
					vIdx = idx
					break
				}
			}
			if vIdx >= 0 && vIdx+3 < len(fields) {
				// positions: vIdx ("verity"), vIdx+1 (version), vIdx+2 (data_dev), vIdx+3 (hash_dev)
				fields[vIdx+2] = "<dev>"
				fields[vIdx+3] = "<dev>"
				lines[i] = strings.Join(fields, " ")
				continue
			}
		}
		// Fallback: leave line unchanged
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}
