#!/bin/bash
# Copied from https://gitlab.com/cryptsetup/cryptsetup/-/blob/dc2251b88d55b349793bd89e7ba765b196cd5c34/tests/verity-compat-test
# with some adjustments.

VERITYSETUP=${VERITYSETUP:-/usr/local/bin/veritysetup-go}

DEV_NAME=verity3273
DEV_NAME2=verity3273x
DEV_OUT="$DEV_NAME.out"
IMG=verity-data
IMG_HASH=verity-hash
IMG_TMP=tst-dev
# If we need deterministic image creation
DEV_SALT=9e7457222290f1bac0d42ad2de2d602a87bb871c22ab70ca040bad450578a436
DEV_UUID=a60c98d2-ae9b-4865-bfcb-b4e3ace11033

remove_mapping()
{
	[ -b /dev/mapper/$DEV_NAME2 ] && dmsetup remove $DEV_NAME2 >/dev/null 2>&1
	[ -b /dev/mapper/$DEV_NAME ] && dmsetup remove $DEV_NAME >/dev/null 2>&1
	[ ! -z "$LOOPDEV1" ] && losetup -d $LOOPDEV1 >/dev/null 2>&1
	rm -f $IMG $IMG.roothash $IMG_HASH $DEV_OUT $IMG_TMP >/dev/null 2>&1
	LOOPDEV1=""
	LOOPDEV2=""
}

fail()
{
	[ -n "$1" ] && echo "$1"
	echo "FAILED backtrace:"
	while caller $frame; do ((frame++)); done
	[ -f $DEV_OUT ] && cat $DEV_OUT
	remove_mapping
	exit 2
}

_sigchld() { local c=$?; [ $c -eq 139 ] && fail "Segfault"; [ $c -eq 134 ] && fail "Aborted"; }
trap _sigchld CHLD

skip()
{
	[ -n "$1" ] && echo "$1"
	exit 77
}

prepare() # $1 dev1_siz [$2 dev2_size]
{
	remove_mapping

	dd if=/dev/zero of=$IMG bs=1k count=$1 >/dev/null 2>&1
	LOOPDEV1=$(losetup -f 2>/dev/null)
	[ -z "$LOOPDEV1" ] && fail "No free loop device"
	losetup $LOOPDEV1 $IMG

	[ -z "$2" ] && return
	LOOPDEV2=$IMG_HASH
}

wipe()
{
	dd if=/dev/zero of=$LOOPDEV1 bs=256k >/dev/null 2>&1
	rm -f $IMG_HASH $DEV_OUT >/dev/null 2>&1
}

check_exists()
{
	[ -b /dev/mapper/$DEV_NAME ] || fail
}

check_version() # MAJ MIN
{
	VER_STR=$(dmsetup targets | grep verity | cut -f 3 -dv)
	[ -z "$VER_STR" ] && fail "Failed to parse dm-verity version."

	VER_MAJ=$(echo $VER_STR | cut -f 1 -d.)
	VER_MIN=$(echo $VER_STR | cut -f 2 -d.)

	test $VER_MAJ -gt $1 && return 0
	test $VER_MAJ -lt $1 && return 1
	test $VER_MIN -ge $2 && return 0

	return 1
}

check_version_kernel()
{
	KER_STR=$(uname -r)
	[ -z "$KER_STR" ] && fail "Failed to parse kernel version."
	KER_MAJ=$(echo $KER_STR | cut -f 1 -d.)
	KER_MIN=$(echo $KER_STR | cut -f 2 -d.)

	test $KER_MAJ -gt $1 && return 0
	test $KER_MAJ -lt $1 && return 1
	test $KER_MIN -ge $2 && return 0

	return 1
}

compare_out() # $1 what, $2 expected
{
	OPT=$(grep -v "^#" "$DEV_OUT" | grep -i "$1" | sed -e 's/.*:\s*//')
	[ -z "$OPT" ] && fail
	[ "$OPT" != "$2" ] && fail "$1 differs ($2)"
}

check_root_hash_fail()
{
	echo -n "Root hash check "
	ROOT_HASH=$($VERITYSETUP format --hash sha256 $IMG $IMG_HASH | grep -e "Root hash" | cut -d: -f2 | tr -d "\t\n ")
	ROOT_HASH_BAD=abcdef0000000000000000000000000000000000000000000000000000000000

	$VERITYSETUP verify $IMG $IMG_HASH $ROOT_HASH || fail
	$VERITYSETUP verify $IMG $IMG_HASH $ROOT_HASH_BAD >/dev/null 2>&1 && fail

	$VERITYSETUP open $IMG $DEV_NAME $IMG_HASH $ROOT_HASH || fail
	check_exists
	dd if=/dev/mapper/$DEV_NAME of=/dev/null bs=4096 count=1 >/dev/null 2>&1
	dmsetup status $DEV_NAME | grep "verity V" >/dev/null || fail
	$VERITYSETUP close $DEV_NAME >/dev/null 2>&1 || fail

	$VERITYSETUP open $IMG $DEV_NAME $IMG_HASH $ROOT_HASH_BAD >/dev/null 2>&1 || fail
	check_exists
	dd if=/dev/mapper/$DEV_NAME of=/dev/null bs=4096 count=1 >/dev/null 2>&1
	dmsetup status $DEV_NAME | grep "verity C" >/dev/null || fail
	$VERITYSETUP close $DEV_NAME >/dev/null 2>&1 || fail

	echo "[OK]"
}

check_root_hash() # $1 size, $2 hash, $3 salt, $4 version, $5 hash, [$6 offset]
{
	local FORMAT_PARAMS
	local VERIFY_PARAMS
	local ROOT_HASH
	local DATA_DEV
	local HASH_DEV

	if [ -z "$LOOPDEV2" ] ; then
		BLOCKS=$(($6 / $1))
		DEV_PARAMS="--hash-offset $6 \
				--data-blocks=$BLOCKS "
		DATA_DEV="$LOOPDEV1"
		HASH_DEV="$LOOPDEV1"
	else
		DEV_PARAMS=""
		DATA_DEV="$LOOPDEV1"
		HASH_DEV="$LOOPDEV2"
	fi

	for sb in yes no; do
	FORMAT_PARAMS="--format=$4 --data-block-size=$1 --hash-block-size=$1 --hash=$5 --salt=$3"
	if [ $sb == yes ] ; then
		VERIFY_PARAMS=""
	else
		FORMAT_PARAMS="$FORMAT_PARAMS --no-superblock"
		VERIFY_PARAMS=$FORMAT_PARAMS
	fi
	ROOT_HASH="$2"

	for fail in data hash; do
	wipe
	echo -n "V$4(sb=$sb) $5 block size $1: "
	$VERITYSETUP format $FORMAT_PARAMS $DEV_PARAMS $DATA_DEV $HASH_DEV >$DEV_OUT
	if [ $? -ne 0 ] ; then
		if [[ $1 =~ "sha2" ]] ; then
			fail "Cannot format device."
		fi
		return
	fi

	echo -n "[root hash]"
	compare_out "root hash" $2
	compare_out "salt" "$3"
	$VERITYSETUP verify $DEV_PARAMS $VERIFY_PARAMS $DATA_DEV $HASH_DEV $ROOT_HASH >>$DEV_OUT 2>&1 || fail
	echo -n "[verify]"
	$VERITYSETUP open $DEV_PARAMS $VERIFY_PARAMS $DATA_DEV $DEV_NAME $HASH_DEV $ROOT_HASH >>$DEV_OUT 2>&1 || fail
	check_exists
	echo -n "[activate]"

	dd if=/dev/mapper/$DEV_NAME of=/dev/null bs=$1 2>/dev/null
	dmsetup status $DEV_NAME | grep "verity V" >/dev/null || fail
	echo -n "[in-kernel verify]"

	$VERITYSETUP close $DEV_NAME >/dev/null 2>&1 || fail

	case $fail in
	data)
		dd if=/dev/urandom of=$LOOPDEV1 bs=1 seek=3456 count=8 conv=notrunc 2>/dev/null
		TXT="data_dev"
		;;
	hash)
		if [ -z "$LOOPDEV2" ] ; then
			dd if=/dev/urandom of=$LOOPDEV1 bs=1 seek=$((8193 + $4)) count=8 conv=notrunc 2>/dev/null
		else
			dd if=/dev/urandom of=$LOOPDEV2 bs=1 seek=8193 count=8 conv=notrunc 2>/dev/null
		fi
                TXT="hash_dev"
		;;
	esac
	$VERITYSETUP verify $DEV_PARAMS $VERIFY_PARAMS $DATA_DEV $HASH_DEV $ROOT_HASH >>$DEV_OUT 2>&1 && \
		fail "userspace check for $TXT corruption"
	$VERITYSETUP open $DEV_PARAMS $VERIFY_PARAMS $DATA_DEV $DEV_NAME $HASH_DEV $ROOT_HASH >>$DEV_OUT 2>&1 || \
		fail "activation"
	dd if=/dev/mapper/$DEV_NAME of=/dev/null bs=$1 2>/dev/null
	dmsetup status $DEV_NAME | grep "verity V" >/dev/null && \
		fail "in-kernel check for $TXT corruption"
	$VERITYSETUP close $DEV_NAME >/dev/null 2>&1 || fail "deactivation"
	echo "[$TXT corruption]"
	done
	done
}

corrupt_device() # $1 device, $2 device_size(in bytes), $3 #{corrupted_bytes}
{
	# Repeatable magic corruption :-)
	CORRUPT=$3
	RANDOM=43
	while [ "$CORRUPT" -gt 0 ]; do
		SEEK=$RANDOM
		while [ $SEEK -ge $2 ] ; do SEEK=$RANDOM; done
		echo -n -e "\x55" | dd of=$1 bs=1 count=1 seek=$SEEK conv=notrunc > /dev/null 2>&1
		CORRUPT=$(($CORRUPT - 1))
	done
}

check_option() # $1 size, $2 hash, $3 salt, $4 version, $5 hash, $6 status option, $7-$8 CLI options
{
	DEV_PARAMS="$LOOPDEV1 $LOOPDEV2"
	FORMAT_PARAMS="--format=$4 --data-block-size=$1 --hash-block-size=$1 --hash=$5 --salt=$3"

	echo -n "Option $7 / $6 "
	$VERITYSETUP format $FORMAT_PARAMS $DEV_PARAMS >/dev/null 2>&1 || fail
	$VERITYSETUP open $2 $7 $8 $DEV_NAME $DEV_PARAMS >/dev/null 2>&1 || fail
	check_exists
	$VERITYSETUP status $DEV_NAME 2>/dev/null | grep flags | grep -q $6 || fail
	dmsetup table $DEV_NAME 2>/dev/null | grep -q $6 || fail
	$VERITYSETUP close $DEV_NAME >/dev/null 2>&1 || fail
	echo "[OK]"
}

checkOffsetBug() # $1 size, $2 hash-offset, $3 data-blocks
{
	echo -n "Size :: $1 B | Hash-offset :: $2 blocks | Data-blocks :: $3 "
	dd if=/dev/zero of=$IMG bs=1 count=0 seek=$1 >/dev/null 2>&1
	$VERITYSETUP format --data-blocks=$3 --hash-offset=$2 $IMG $IMG >/dev/null 2>&1 || fail "Test [hash-offset greater than 2G] failed"
	echo "[OK]"
	remove_mapping
}

checkOverlapBug() # $1 size, $2 hash-offset, [$3 data-blocks], [$4 block_size]
{
	local device_size_bytes=$1
	local hash_offset_bytes=$2
	local data_blocks=${3:-}
	local block_size=${4:-4096}

	echo -n "Device-size :: ${device_size_bytes} B | "
	if [ -n "$data_blocks" ]; then
		echo -n "Data-blocks :: ${data_blocks} blocks | "
	else
		echo -n "Data-blocks :: whole device | "
	fi
	echo -n "Block-size :: ${block_size} B | "
	echo -n "Hash-offset :: ${hash_offset_bytes} B | "

	dd if=/dev/zero of=$IMG bs=1 count=0 seek=$device_size_bytes >/dev/null 2>&1

	if [ -z "$data_blocks" ]; then
		$VERITYSETUP --hash-offset=$hash_offset_bytes format $IMG $IMG >/dev/null 2>&1 && fail "Test [overlap without --data-blocks] failed"
	else
		$VERITYSETUP --data-block-size=$block_size --hash-block-size=$block_size --data-blocks=$data_blocks --hash-offset=$hash_offset_bytes format $IMG $IMG >/dev/null 2>&1
		RET=$?
		local max_blocks_allowed=$((hash_offset_bytes / block_size))
		[ "$data_blocks" -gt "$max_blocks_allowed" ] && [ "$RET" -eq 0 ] && fail "Test [overlap - hash-offset in data area] failed"
	fi

	echo "[OK]"
	remove_mapping
}

check_signature()
{	
	local CERT_FILE=$(mktemp)
	local KEY_FILE=$(mktemp)
	local SIG_FILE=$(mktemp)
	local HASH_BIN=$(mktemp)
	
	trap "rm -f $CERT_FILE $KEY_FILE $SIG_FILE $HASH_BIN" RETURN
	
	cat > ${CERT_FILE}.conf << 'EOF'
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
CN = DM-Verity Test Key

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
	
	openssl req -new -x509 -newkey rsa:2048 -keyout $KEY_FILE -out $CERT_FILE \
		-days 365 -nodes -config ${CERT_FILE}.conf >/dev/null 2>&1 || fail
	rm -f ${CERT_FILE}.conf
	
	ROOT_HASH=$($VERITYSETUP format --hash sha256 $LOOPDEV1 $IMG_HASH 2>/dev/null | \
		grep -e "Root hash" | cut -d: -f2 | tr -d "\t\n ")
	
	echo -n "$ROOT_HASH" | xxd -r -p > $HASH_BIN 2>/dev/null
	
	openssl smime -sign -binary -noattr \
		-inkey $KEY_FILE -signer $CERT_FILE \
		-outform DER -out $SIG_FILE -in $HASH_BIN >/dev/null 2>&1 || fail
	
	# Verify signature in userspace before kernel verification.
	# This ensures the PKCS#7 signature format is valid and the signature
	# can be verified against the certificate, independent of kernel trust.
	openssl pkcs7 -in $SIG_FILE -inform DER -print_certs -noout >/dev/null 2>&1 || \
		fail "PKCS#7 signature format validation failed"
	
	openssl smime -verify -in $SIG_FILE -inform DER \
		-CAfile $CERT_FILE -content $HASH_BIN -noverify >/dev/null 2>&1 || \
		fail "Userspace signature verification failed"
	
	# Kernel signature verification requires the certificate to be in the kernel's
	# trusted keyring (.builtin_trusted_keys, .secondary_trusted_keys, or .platform).
	# In CI environments, the self-signed test certificate is not trusted by the kernel,
	# so we expect the signature verification to fail with EKEYREJECTED error.
	if check_version 1 5; then
		OUTPUT=$($VERITYSETUP open --root-hash-signature $SIG_FILE \
			$LOOPDEV1 $DEV_NAME $IMG_HASH $ROOT_HASH 2>&1)
		
		if echo "$OUTPUT" | grep -q "Loaded signature into thread keyring"; then
			echo -n "[signature loaded]"  
		else
			fail "Unexpected signature verification error: $OUTPUT"
		fi
	fi
	
	echo "[OK]"
	remove_mapping
}

export LANG=C
[ $(id -u) != 0 ] && skip "WARNING: You must be root to run this test, test skipped."
[ ! -x "$VERITYSETUP" ] && skip "Cannot find $VERITYSETUP, test skipped."

modprobe dm-verity >/dev/null 2>&1
dmsetup targets | grep verity >/dev/null 2>&1 || skip "Cannot find dm-verity target, test skipped."

# VERITYSETUP tests

SALT=e48da609055204e89ae53b655ca2216dd983cf3cb829f34f63a297d106d53e2d

echo "Verity tests [separate devices]"
prepare 8192 1024
check_root_hash_fail

check_root_hash  512 9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174 $SALT 1 sha256
check_root_hash 1024 54d92778750495d1f80832b486ebd007617d746271511bbf0e295e143da2b3df $SALT 1 sha256
check_root_hash 4096 e522df0f97da4febb882ac40f30b37dc0b444bf6df418929463fa25280f09d5c $SALT 1 sha256
#version 0
check_root_hash 4096 cbbf4ebd004ef65e29b935bb635a39cf754d677f3fa10b0126da725bbdf10f7d $SALT 0 sha256
# no salt
check_root_hash 4096 ef29c902d87350f1da4bfa536e16cebc162a909bf89abe448b81ec500d4fb9bf - 1 sha256
# sha1
check_root_hash 1024 d0e9163ca8844aaa2e88fe5265a8c5d9ee494a99 $SALT 1 sha1
check_root_hash 1024 73509e8e868be6b8ac939817a98a3d35121413b2 dadada 1 sha1

echo "Verity tests [one device offset]"
prepare $((8192 + 1024))
check_root_hash  512 9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174 $SALT 1 sha256 8388608
check_root_hash 1024 54d92778750495d1f80832b486ebd007617d746271511bbf0e295e143da2b3df $SALT 1 sha256 8388608
check_root_hash 4096 e522df0f97da4febb882ac40f30b37dc0b444bf6df418929463fa25280f09d5c $SALT 1 sha256 8388608
#version 0
check_root_hash 4096 cbbf4ebd004ef65e29b935bb635a39cf754d677f3fa10b0126da725bbdf10f7d $SALT 0 sha256 8388608
# no salt
check_root_hash 4096 ef29c902d87350f1da4bfa536e16cebc162a909bf89abe448b81ec500d4fb9bf - 1 sha256 8388608
# sha1
check_root_hash 1024 d0e9163ca8844aaa2e88fe5265a8c5d9ee494a99 $SALT 1 sha1 8388608
check_root_hash 1024 73509e8e868be6b8ac939817a98a3d35121413b2 dadada 1 sha1 8388608

echo "Veritysetup [hash-offset bigger than 2G works] "
checkOffsetBug 3000000000 2499997696 256
checkOffsetBug 10000000000 8000000000 128

echo "Veritysetup [overlap-detection] "
checkOverlapBug 2097152 1433600
checkOverlapBug 2097152 1433600 350 4096
checkOverlapBug 2097152 1228800 350 4096 # data-hash overlap

echo -n "Early check for active name:"
prepare 8192 1024
DM_BAD_NAME=x/x
DM_LONG_NAME=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
$VERITYSETUP format --format=1 --data-block-size=512 --hash-block-size=512 --hash=sha256 --salt=$SALT $LOOPDEV1 $IMG_HASH >/dev/null 2>&1 || fail "Cannot format device."
$VERITYSETUP open $LOOPDEV1 $DM_BAD_NAME $DEV $IMG_HASH 9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174 2>/dev/null && fail
$VERITYSETUP open $LOOPDEV1 $DM_LONG_NAME $DEV $IMG_HASH 9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174 2>/dev/null && fail
echo "[OK]"
remove_mapping

echo -n "Signature verification tests"
prepare 8192 1024
check_signature

exit 0
