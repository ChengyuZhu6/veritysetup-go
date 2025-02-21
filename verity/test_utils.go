package verity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
)

// createTestDevice creates a test device file with random data
func createTestDevice(size uint64) (string, error) {
	// Create temp file
	f, err := os.CreateTemp("", "verity-test-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}
	defer f.Close()

	// Write random data
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to generate random data: %v", err)
	}

	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to write data: %v", err)
	}

	return f.Name(), nil
}

// createTestParams creates test verity parameters
func createTestParams() *VerityParams {
	return &VerityParams{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataSize:       1024 * 1024 / 4096, // 1MB in blocks
		HashType:       1,
		Salt:           make([]byte, 32), // veritysetup uses 32-byte salt by default
		SaltSize:       32,
		HashAreaOffset: 4096, // Start after first block
	}
}

// setupTestData 准备测试数据
func setupTestData(t *testing.T, dataPath, hashPath string, dataSize uint64) {
	t.Helper()

	data := make([]byte, dataSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}
	if err := os.WriteFile(dataPath, data, 0644); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	// Use the same block size as in the test parameters
	hashSize := calculateHashDeviceSize(dataSize, 4096, 32)
	hashData := make([]byte, hashSize)
	if err := os.WriteFile(hashPath, hashData, 0644); err != nil {
		t.Fatalf("Failed to create hash file: %v", err)
	}
}

// setupVerityTestParams 创建测试参数
func setupVerityTestParams(dataSize uint64) *VerityParams {
	return &VerityParams{
		HashName:       "sha256",
		DataBlockSize:  4096,
		HashBlockSize:  4096,
		DataSize:       dataSize / 4096,
		HashType:       1,
		Salt:           make([]byte, 32), // 使用32字节的空salt，与 veritysetup 默认值保持一致
		SaltSize:       32,
		HashAreaOffset: 4096, // 从第一个块之后开始
	}
}

// calculateHashDeviceSize 计算哈希设备大小
func calculateHashDeviceSize(dataSize uint64, blockSize uint32, hashSize uint32) uint64 {
	blocks := dataSize / uint64(blockSize)
	if dataSize%uint64(blockSize) != 0 {
		blocks++
	}

	totalBlocks := uint64(0)
	remainingBlocks := blocks
	hashPerBlock := blockSize / hashSize

	for remainingBlocks > 1 {
		remainingBlocks = (remainingBlocks + uint64(hashPerBlock) - 1) / uint64(hashPerBlock)
		totalBlocks += remainingBlocks
	}

	return totalBlocks * uint64(blockSize)
}

// getVeritySetupRootHash 获取 veritysetup 的根哈希
func getVeritySetupRootHash(t *testing.T, dataPath string, hashPath string, params *VerityParams) ([]byte, error) {
	// 构造veritysetup命令
	cmd := exec.Command("veritysetup", "format", "--no-superblock",
		dataPath, hashPath+".verity",
		"--hash="+params.HashName,
		"--data-block-size="+strconv.Itoa(int(params.DataBlockSize)),
		"--hash-block-size="+strconv.Itoa(int(params.HashBlockSize)),
		"--salt="+hex.EncodeToString(params.Salt),
	)

	// 执行并解析输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("veritysetup failed: %v\nOutput: %s", err, output)
	}

	// 从输出中提取root hash
	re := regexp.MustCompile(`Root hash:\s+([0-9a-fA-F]+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return nil, fmt.Errorf("failed to parse root hash from output")
	}

	rootHash, err := hex.DecodeString(matches[1])
	if err != nil {
		return nil, fmt.Errorf("invalid root hash format: %v", err)
	}

	return rootHash, nil
}

// readFileContent reads the entire content of a file
func readFileContent(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return content, nil
}
