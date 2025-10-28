set -euo pipefail
ALG="${1:-sha256}"

DATA=data.img
OUR=hash.img
VS=$OUR.verity
DBS=4096
HBS=4096
SIZE=$((1024*1024))

case "$ALG" in
  sha256)
    # SetupVerityTestParams: 32字节全0盐
    SALT_HEX=$(printf '00%.0s' {1..32})
    ;;
  sha512)
    # 用例中盐是 "test-salt"
    SALT_HEX=$(printf 'test-salt' | xxd -p -c999)
    ;;
  *) echo "alg must be sha256 or sha512"; exit 2;;
esac

# 1) 准备 1MB 数据
dd if=/dev/urandom of="$DATA" bs="$SIZE" count=1 status=none
cat > gen_hash.go <<'EOF'
package main
import (
  "encoding/hex"
  "fmt"
  "os"
  "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
)
func must(err error){ if err!=nil { panic(err) } }
func main(){
  data, out, alg := os.Args[1], os.Args[2], os.Args[3]
  var dbs, hbs uint32; var saltHex string
  _,_ = fmt.Sscanf(os.Args[4], "%d", &dbs)
  _,_ = fmt.Sscanf(os.Args[5], "%d", &hbs)
  saltHex = os.Args[6]
  fi, err := os.Stat(data); must(err)
  size := uint64(fi.Size())
  if size%uint64(dbs)!=0 { panic("data not aligned") }
  blocks := size/uint64(dbs)
  salt, err := hex.DecodeString(saltHex); must(err)
  p := verity.DefaultVerityParams()
  p.HashName = alg
  p.DataBlockSize = dbs
  p.HashBlockSize = hbs
  p.DataBlocks = blocks
  p.HashType = 1
  p.Salt = salt
  p.SaltSize = uint16(len(salt))
  p.NoSuperblock = true
  must(verity.SetupTestData(data, out, &p, size))
  vh := verity.NewVerityHash(&p, data, out, nil)
  must(vh.Create())
  fmt.Printf("our root: %x\n", vh.GetRootHash())
}
EOF
OUR_ROOT=$(go run gen_hash.go "$DATA" "$OUR" "$ALG" "$DBS" "$HBS" "$SALT_HEX" | grep "our root:" | awk '{print $3}')
echo "veritysetup-go root hash: $OUR_ROOT"

# 3) veritysetup 生成 hash.img.verity（同参数）
VS_OUTPUT=$(veritysetup format \
  --hash "$ALG" \
  --no-superblock \
  --data-block-size "$DBS" \
  --hash-block-size "$HBS" \
  --salt "$SALT_HEX" \
  --uuid "00000000-0000-0000-0000-000000000000" \
  "$DATA" "$VS" 2>&1)

VS_ROOT=$(echo "$VS_OUTPUT" | grep "Root hash:" | awk '{print $3}')
echo "veritysetup root hash:    $VS_ROOT"

echo ""
echo "=== File Comparison ==="
echo "veritysetup-go: $OUR ($(stat -f%z "$OUR" 2>/dev/null || stat -c%s "$OUR" 2>/dev/null) bytes)"
echo "veritysetup:    $VS ($(stat -f%z "$VS" 2>/dev/null || stat -c%s "$VS" 2>/dev/null) bytes)"

# 4) 验证 root hash 是否一致
echo ""
echo "=== Root Hash Verification ==="
if [ "$OUR_ROOT" = "$VS_ROOT" ]; then
  echo "✓ Root hashes match!"
else
  echo "✗ Root hashes differ!"
  exit 1
fi

# 5) 使用 veritysetup verify 验证 veritysetup-go 生成的 hash 文件
# 注意：verify 命令需要将 root hash 作为最后一个参数
echo ""
echo "=== Verifying veritysetup-go output with veritysetup ==="
if veritysetup verify \
  --hash "$ALG" \
  --no-superblock \
  --data-block-size "$DBS" \
  --hash-block-size "$HBS" \
  --salt "$SALT_HEX" \
  "$DATA" "$OUR" "$OUR_ROOT" 2>&1; then
  echo "✓ veritysetup successfully verified veritysetup-go's hash file!"
else
  echo "✗ veritysetup verification failed for veritysetup-go's hash file!"
  exit 1
fi

# 6) 同样验证 veritysetup 自己生成的文件（作为对照）
echo ""
echo "=== Verifying veritysetup output with veritysetup ==="
if veritysetup verify \
  --hash "$ALG" \
  --no-superblock \
  --data-block-size "$DBS" \
  --hash-block-size "$HBS" \
  --salt "$SALT_HEX" \
  "$DATA" "$VS" "$VS_ROOT" 2>&1; then
  echo "✓ veritysetup successfully verified its own hash file!"
else
  echo "✗ veritysetup verification failed for its own hash file!"
  exit 1
fi

echo ""
echo "=== All Verifications Passed! ==="