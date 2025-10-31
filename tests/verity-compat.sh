#!/bin/bash

set -euo pipefail

VERITYSETUP=${VERITYSETUP:-veritysetup}
VERITYSETUP_GO=${VERITYSETUP_GO:-veritysetup-go}
SALT_DEFAULT="e48da609055204e89ae53b655ca2216dd983cf3cb829f34f63a297d106d53e2d"
DATA_SIZE_KB=8192

WORKDIR=$(mktemp -d -t verity-compat-XXXXXX)

LOOP_GO_DATA=""
LOOP_GO_HASH=""
LOOP_REF_DATA=""
LOOP_REF_HASH=""

cleanup() {
	set +e
	for dev in verity-compat-ref verity-compat-go; do
		if dmsetup info "$dev" >/dev/null 2>&1; then
			dmsetup remove "$dev" >/dev/null 2>&1
		fi
	done

	for loopdev in "$LOOP_GO_DATA" "$LOOP_GO_HASH" "$LOOP_REF_DATA" "$LOOP_REF_HASH"; do
		if [ -n "$loopdev" ] && losetup "$loopdev" >/dev/null 2>&1; then
			losetup -d "$loopdev" >/dev/null 2>&1
		fi
	done

	rm -rf "$WORKDIR"
}
trap cleanup EXIT

extract_root_hash() {
	sed -n 's/^Root hash:\s*//p' | tr -d ' \t\n\r'
}

run_format() {
	local bin=$1
	shift
	set +e
	local out
	local rc
	out=$("${bin}" format "$@" 2>&1)
	rc=$?
	set -e
	printf '%s' "$out"
	return $rc
}

run_verify() {
	local bin=$1
	shift
	set +e
	local out
	out=$("${bin}" verify "$@" 2>&1)
	local rc=$?
	set -e
	printf '%s' "$out"
	return $rc
}

run_open() {
	local bin=$1
	shift
	set +e
	local out
	out=$("${bin}" open "$@" 2>&1)
	local rc=$?
	set -e
	printf '%s' "$out"
	return $rc
}

# Format test matrix (case|block_size|hash_algo|salt|format_version|expected_root|is_primary)
FORMAT_CASES=(
	"v1_block512_sha256|512|sha256|${SALT_DEFAULT}|1|9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174|0"
	"v1_block1024_sha256|1024|sha256|${SALT_DEFAULT}|1|54d92778750495d1f80832b486ebd007617d746271511bbf0e295e143da2b3df|0"
	"v1_block4096_sha256|4096|sha256|${SALT_DEFAULT}|1|e522df0f97da4febb882ac40f30b37dc0b444bf6df418929463fa25280f09d5c|1"
	"v0_block4096_sha256|4096|sha256|${SALT_DEFAULT}|0|cbbf4ebd004ef65e29b935bb635a39cf754d677f3fa10b0126da725bbdf10f7d|0"
	"nosalt_block4096_sha256|4096|sha256|-|1|ef29c902d87350f1da4bfa536e16cebc162a909bf89abe448b81ec500d4fb9bf|0"
	"v1_block1024_sha1|1024|sha1|${SALT_DEFAULT}|1|d0e9163ca8844aaa2e88fe5265a8c5d9ee494a99|0"
	"v1_block1024_sha1_salt_dadada|1024|sha1|dadada|1|73509e8e868be6b8ac939817a98a3d35121413b2|0"
)

PRIMARY_CASE=""
PRIMARY_ROOT=""
PRIMARY_BLOCK=""
PRIMARY_HASH_ALGO=""
PRIMARY_SALT=""
PRIMARY_FORMAT=""

run_format_case() {
	local descriptor=$1
	IFS='|' read -r case_name block_size hash_algo salt_hex format_version expected_root is_primary <<<"$descriptor"

	local data_file="${WORKDIR}/${case_name}.data"
	local hash_ref_file="${WORKDIR}/${case_name}.hash.ref"
	local hash_go_file="${WORKDIR}/${case_name}.hash.go"

	dd if=/dev/zero of="${data_file}" bs=1K count=${DATA_SIZE_KB} status=none
	: >"${hash_ref_file}"
	: >"${hash_go_file}"

	local data_blocks=$((DATA_SIZE_KB * 1024 / block_size))
	local -a format_opts
	format_opts=(--hash "${hash_algo}" --data-block-size "${block_size}" --hash-block-size "${block_size}" --data-blocks "${data_blocks}")
	if [ -n "${format_version}" ]; then
		format_opts+=(--format "${format_version}")
	fi
	if [ -n "${salt_hex}" ]; then
		format_opts+=(--salt "${salt_hex}")
	fi

	local out_ref
	if ! out_ref=$(run_format "${VERITYSETUP}" "${format_opts[@]}" "${data_file}" "${hash_ref_file}"); then
		echo "[${case_name}] reference veritysetup format failed"
		echo "${out_ref}"
		exit 1
	fi
	local root_ref
	root_ref=$(printf '%s' "${out_ref}" | extract_root_hash)
	if [ -z "${root_ref}" ]; then
		echo "[${case_name}] failed to parse root hash from reference output"
		echo "${out_ref}"
		exit 1
	fi
	if [ "${root_ref}" != "${expected_root}" ]; then
		echo "[${case_name}] reference root hash mismatch"
		echo "expected: ${expected_root}"
		echo "actual:   ${root_ref}"
		exit 1
	fi

	local peer_opts=("${format_opts[@]}")
	local out_go
	if ! out_go=$(run_format "${VERITYSETUP_GO}" "${peer_opts[@]}" "${data_file}" "${hash_go_file}"); then
		echo "[${case_name}] veritysetup-go format failed"
		echo "${out_go}"
		exit 1
	fi
	local root_go
	root_go=$(printf '%s' "${out_go}" | extract_root_hash)
	if [ -z "${root_go}" ]; then
		echo "[${case_name}] failed to parse root hash from veritysetup-go output"
		echo "${out_go}"
		exit 1
	fi
	if [ "${root_go}" != "${expected_root}" ]; then
		echo "[${case_name}] veritysetup-go root hash mismatch"
		echo "expected: ${expected_root}"
		echo "actual:   ${root_go}"
		exit 1
	fi

	if [ "${root_go}" != "${root_ref}" ]; then
		echo "[${case_name}] root hashes differ between binaries"
		echo "reference: ${root_ref}"
		echo "go:        ${root_go}"
		exit 1
	fi

	echo "  -> ${case_name}: ${root_go}"

	if [ "${is_primary}" = "1" ]; then
		PRIMARY_CASE="${case_name}"
		PRIMARY_ROOT="${root_go}"
		PRIMARY_BLOCK="${block_size}"
		PRIMARY_HASH_ALGO="${hash_algo}"
		PRIMARY_SALT="${salt_hex}"
		PRIMARY_FORMAT="${format_version}"
	fi
}

echo "[Format] Validating deterministic roots against reference veritysetup"
for case in "${FORMAT_CASES[@]}"; do
	run_format_case "$case"
done

if [ -z "${PRIMARY_CASE}" ]; then
	echo "Primary format case was not selected"
	exit 1
fi

echo
DATA_FILE="${WORKDIR}/${PRIMARY_CASE}.data"
HASH_REF="${WORKDIR}/${PRIMARY_CASE}.hash.ref"
HASH_GO="${WORKDIR}/${PRIMARY_CASE}.hash.go"
ROOT_HASH_FILE="${WORKDIR}/${PRIMARY_CASE}.root"
ROOT_GO="${PRIMARY_ROOT}"

printf '%s' "${ROOT_GO}" >"${ROOT_HASH_FILE}"

PRIMARY_ARGS=(--hash "${PRIMARY_HASH_ALGO}" --data-block-size "${PRIMARY_BLOCK}" --hash-block-size "${PRIMARY_BLOCK}")
if [ -n "${PRIMARY_SALT}" ]; then
	PRIMARY_ARGS+=(--salt "${PRIMARY_SALT}")
fi

echo "[1] Root hash (${PRIMARY_CASE}): ${ROOT_GO}"

echo "[2] Verify parity"
if ! run_verify "${VERITYSETUP}" "${DATA_FILE}" "${HASH_REF}" "${ROOT_GO}" "${PRIMARY_ARGS[@]}" >/dev/null; then
	echo "Reference veritysetup verify failed"
	exit 1
fi
if ! run_verify "${VERITYSETUP_GO}" "${DATA_FILE}" "${HASH_GO}" "${ROOT_GO}" "${PRIMARY_ARGS[@]}" >/dev/null; then
	echo "veritysetup-go verify failed"
	exit 1
fi
echo "  -> Both verify operations succeeded"

echo "[3] Detect data corruption"
TMP_CORRUPT="${WORKDIR}/corrupt"
cp "${DATA_FILE}" "${TMP_CORRUPT}"
orig_byte=$(dd if="${TMP_CORRUPT}" bs=1 count=1 skip=4096 status=none | od -An -t u1 | tr -d ' ')
if [ -z "${orig_byte}" ]; then
	echo "Failed to read byte at offset 4096"
	exit 1
fi
corrupted_byte=$(( (orig_byte ^ 0xFF) & 0xFF ))
printf '\\x%02x' "${corrupted_byte}" | dd of="${TMP_CORRUPT}" bs=1 seek=4096 conv=notrunc status=none

set +e
run_verify "${VERITYSETUP}" "${TMP_CORRUPT}" "${HASH_REF}" "${ROOT_GO}" "${PRIMARY_ARGS[@]}" >/dev/null 2>&1
REF_STATUS=$?
run_verify "${VERITYSETUP_GO}" "${TMP_CORRUPT}" "${HASH_GO}" "${ROOT_GO}" "${PRIMARY_ARGS[@]}" >/dev/null 2>&1
GO_STATUS=$?
set -e

if [ ${REF_STATUS} -eq 0 ] || [ ${GO_STATUS} -eq 0 ]; then
	echo "Verification unexpectedly succeeded after corruption"
	exit 1
fi
echo "  -> Both binaries detected corruption"

echo "[4] Device activation parity"
DATA_LOOP_GO_FILE="${WORKDIR}/data-loop-go"
HASH_LOOP_GO_FILE="${WORKDIR}/hash-loop-go"
DATA_LOOP_REF_FILE="${WORKDIR}/data-loop-ref"
HASH_LOOP_REF_FILE="${WORKDIR}/hash-loop-ref"

cp "${DATA_FILE}" "${DATA_LOOP_GO_FILE}"
cp "${HASH_GO}" "${HASH_LOOP_GO_FILE}"
cp "${DATA_FILE}" "${DATA_LOOP_REF_FILE}"
cp "${HASH_REF}" "${HASH_LOOP_REF_FILE}"

LOOP_GO_DATA=$(losetup -f --show "${DATA_LOOP_GO_FILE}")
LOOP_GO_HASH=$(losetup -f --show "${HASH_LOOP_GO_FILE}")

if ! run_open "${VERITYSETUP_GO}" "${LOOP_GO_DATA}" verity-compat-go "${LOOP_GO_HASH}" "${ROOT_GO}" "${PRIMARY_ARGS[@]}" >/dev/null; then
	echo "veritysetup-go open failed"
	exit 1
fi

dmsetup table verity-compat-go >/dev/null
echo "  -> veritysetup-go activated device successfully"

echo "[5] Reference activation"
LOOP_REF_DATA=$(losetup -f --show "${DATA_LOOP_REF_FILE}")
LOOP_REF_HASH=$(losetup -f --show "${HASH_LOOP_REF_FILE}")

if ! run_open "${VERITYSETUP}" "${LOOP_REF_DATA}" verity-compat-ref "${LOOP_REF_HASH}" "${ROOT_GO}" "${PRIMARY_ARGS[@]}" >/dev/null; then
	echo "Reference veritysetup open failed"
	exit 1
fi

dmsetup table verity-compat-ref >/dev/null
echo "  -> Reference veritysetup activated device successfully"

echo "[6] Device close"
"${VERITYSETUP_GO}" close verity-compat-go >/dev/null
"${VERITYSETUP}" close verity-compat-ref >/dev/null

echo "All compatibility tests passed"

for loopdev in LOOP_GO_DATA LOOP_GO_HASH LOOP_REF_DATA LOOP_REF_HASH; do
	val=${!loopdev}
	if [ -n "$val" ] && losetup "$val" >/dev/null 2>&1; then
		losetup -d "$val" >/dev/null 2>&1
	fi
	eval "$loopdev=\"\""
done
