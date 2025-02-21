package verity

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// testCreateAndVerify 测试创建和验证过程
func testCreateAndVerify(t *testing.T, params *VerityParams, dataPath, hashPath string) error {
	t.Helper()

	// 创建哈希
	vh := NewVerityHash(params, dataPath, hashPath, make([]byte, 32))
	if err := vh.Create(); err != nil {
		return fmt.Errorf("hash creation failed: %w", err)
	}

	// 保存根哈希
	rootHash := make([]byte, 32)
	copy(rootHash, vh.rootHash)
	t.Logf("our root hash: %x", rootHash)

	// 验证哈希
	vh = NewVerityHash(params, dataPath, hashPath, rootHash)
	t.Logf("our root hash: %x", vh.rootHash)
	if err := vh.Verify(); err != nil {
		return fmt.Errorf("hash verification failed: %w", err)
	}

	return nil
}

// TestVerityHash 测试哈希创建和验证
func TestVerityHash(t *testing.T) {
	tests := []struct {
		name     string
		dataSize uint64
		wantErr  bool
	}{
		{
			name:     "small file (1MB)",
			dataSize: 1024 * 1024,
			wantErr:  false,
		},
		{
			name:     "medium file (10MB)",
			dataSize: 10 * 1024 * 1024,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 准备临时文件
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			// 创建测试数据和参数
			setupTestData(t, dataPath, hashPath, tt.dataSize)
			params := setupVerityTestParams(tt.dataSize)

			// 测试创建和验证
			if err := testCreateAndVerify(t, params, dataPath, hashPath); (err != nil) != tt.wantErr {
				t.Errorf("testCreateAndVerify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestVerityHashDataCorruption 测试哈希数据损坏
func TestVerityHashDataCorruption(t *testing.T) {
	// 准备测试环境
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.img")
	hashPath := filepath.Join(tmpDir, "hash.img")
	dataSize := uint64(1024 * 1024) // 1MB

	setupTestData(t, dataPath, hashPath, dataSize)
	params := setupVerityTestParams(dataSize)

	// 创建初始哈希
	vh := NewVerityHash(params, dataPath, hashPath, make([]byte, 32))
	if err := vh.Create(); err != nil {
		t.Fatalf("Failed to create initial hash: %v", err)
	}

	// 保存根哈希
	rootHash := make([]byte, 32)
	copy(rootHash, vh.rootHash)

	// 修改数据并验证失败
	f, err := os.OpenFile(dataPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("Failed to open data file: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteAt([]byte{0xFF}, 1000); err != nil {
		t.Fatalf("Failed to modify data: %v", err)
	}

	// 验证应该失败
	vh = NewVerityHash(params, dataPath, hashPath, rootHash)
	if err := vh.Verify(); err == nil {
		t.Error("Verification should fail with corrupted data")
	}
}

// TestAgainstVeritySetup 优化与 veritysetup 的对比测试
func TestAgainstVeritySetup(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup not found in PATH")
	}

	tests := []struct {
		name     string
		dataSize uint64
	}{
		{"1MB file", 1024 * 1024},
		{"4MB file", 4 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dataPath := filepath.Join(tmpDir, "data.img")
			hashPath := filepath.Join(tmpDir, "hash.img")

			params := setupVerityTestParams(tt.dataSize)
			setupTestData(t, dataPath, hashPath, tt.dataSize)

			// 比较实现
			if err := compareVerityImplementations(t, params, dataPath, hashPath); err != nil {
				t.Errorf("Implementation comparison failed: %v", err)
			}
		})
	}
}

// compareVerityImplementations 比较我们的实现与 veritysetup
func compareVerityImplementations(t *testing.T, params *VerityParams, dataPath, hashPath string) error {
	// 准备测试数据
	setupTestData(t, dataPath, hashPath, params.DataSize*uint64(params.DataBlockSize))

	// 使用我们的实现生成哈希
	ourVh := NewVerityHash(params, dataPath, hashPath, make([]byte, 32))
	if err := ourVh.Create(); err != nil {
		return fmt.Errorf("our implementation create failed: %w", err)
	}

	// 保存我们生成的hash文件内容
	ourHashContent, err := readFileContent(hashPath)
	if err != nil {
		return fmt.Errorf("failed to read our hash file: %w", err)
	}

	// 使用veritysetup生成哈希
	veritysetupHashPath := hashPath + ".verity"
	veritysetupRootHash, err := getVeritySetupRootHash(t, dataPath, hashPath, params)
	if err != nil {
		return fmt.Errorf("veritysetup failed: %w", err)
	}

	// 读取veritysetup生成的hash文件内容
	veritysetupHashContent, err := readFileContent(veritysetupHashPath)
	if err != nil {
		return fmt.Errorf("failed to read veritysetup hash file: %w", err)
	}
	// 比较root hash
	if !bytes.Equal(ourVh.rootHash, veritysetupRootHash) {
		return fmt.Errorf("root hash mismatch\nOur: %x\nVeritysetup: %x",
			ourVh.rootHash, veritysetupRootHash)
	}

	// 比较hash文件内容
	// 注意：我们只比较从HashAreaOffset开始的内容，因为veritysetup可能在开头有额外的元数据
	ourHashData := ourHashContent[params.HashAreaOffset:]
	veritysetupHashData := veritysetupHashContent[params.HashAreaOffset:]

	if !bytes.Equal(ourHashData, veritysetupHashData) {
		return fmt.Errorf("hash file content mismatch from offset %d\nOur hash len: %d\nVeritysetup hash len: %d",
			params.HashAreaOffset, len(ourHashData), len(veritysetupHashData))
	}

	return nil
}
