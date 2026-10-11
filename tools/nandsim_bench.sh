#!/usr/bin/env bash
# Build JFFS2 or UBIFS benchmark images with the real kernel drivers on simulated NAND.
#
# Usage:  sudo tools/nandsim_bench.sh jffs2      (or ubifs)
# Tunables through the environment: SEEDS, OPS, CHURNS, OUT, COMPR, PARTITION_EBS.
#
# Needs a Linux host with root, the nandsim, mtdblock, jffs2, ubi and ubifs modules,
# mtd-utils (flash_erase, ubiformat, ubiattach, ubimkvol, ubidetach) and python3.
# The build sandbox for Revenant had no kernel module access, so this script was
# written against the documented tools but never executed there. Run it on a
# disposable virtual machine first and read each step before trusting the output.
#
# COMPR=none is the default because it keeps the survival oracle exact, since a raw
# token search cannot see compressed data. Set COMPR=default to use the kernel's
# normal compressor, and survival in the results then becomes a lower bound.

set -euo pipefail

FS="${1:-jffs2}"
SEEDS="${SEEDS:-5}"
OPS="${OPS:-60}"
CHURNS="${CHURNS:-0 50 200 800}"
OUT="${OUT:-$(pwd)/nand_bench}"
COMPR="${COMPR:-none}"
PARTITION_EBS="${PARTITION_EBS:-128}"   # 128 erase blocks of 128 KiB gives a 16 MiB test partition
MNT=/mnt/revenant_bench
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then echo "Run this with sudo, it loads kernel modules."; exit 1; fi
case "$FS" in jffs2|ubifs) ;; *) echo "First argument must be jffs2 or ubifs."; exit 1 ;; esac
for tool in modprobe flash_erase python3 dd; do
  command -v "$tool" >/dev/null || { echo "Missing $tool, install mtd-utils and python3."; exit 1; }
done
if [ "$FS" = ubifs ]; then
  for tool in ubiformat ubiattach ubimkvol ubidetach; do
    command -v "$tool" >/dev/null || { echo "Missing $tool from mtd-utils."; exit 1; }
  done
fi

mkdir -p "$OUT" "$MNT"

# A 128 MiB part with 2 KiB pages and 128 KiB erase blocks, split so the first
# partition is small enough for garbage collection to matter during churn.
if ! grep -q "NAND simulator" /proc/mtd; then
  modprobe nandsim first_id_byte=0x20 second_id_byte=0xa1 third_id_byte=0x00 fourth_id_byte=0x15 \
    parts="$PARTITION_EBS"
fi
MTD="$(grep -m1 "NAND simulator partition 0" /proc/mtd | cut -d: -f1 || true)"
[ -n "$MTD" ] || MTD="$(grep -m1 "NAND simulator" /proc/mtd | cut -d: -f1)"
NUM="${MTD#mtd}"
echo "Using /dev/$MTD for $FS, compression $COMPR, output in $OUT"

mount_fs() {
  local opts=""
  [ "$COMPR" != default ] && opts="-o compr=$COMPR"
  if [ "$FS" = jffs2 ]; then
    flash_erase -j -q "/dev/$MTD" 0 0
    mount -t jffs2 $opts "$MTD" "$MNT"
  else
    modprobe ubi
    flash_erase -q "/dev/$MTD" 0 0
    ubiformat -y -q "/dev/$MTD"
    ubiattach -m "$NUM" -d 7 >/dev/null
    ubimkvol /dev/ubi7 -N bench -m >/dev/null
    mount -t ubifs $opts ubi7:bench "$MNT"
  fi
}

unmount_fs() {
  sync
  umount "$MNT"
  if [ "$FS" = ubifs ]; then ubidetach -d 7; fi
}

compressed_flag=""
[ "$COMPR" != none ] && compressed_flag="--compressed"

for churn in $CHURNS; do
  for seed in $(seq 0 $((SEEDS - 1))); do
    name="${FS}_nand_s${seed}_c${churn}.img"
    mount_fs
    python3 "$HERE/workload.py" mounted --dir "$MNT" --seed "$seed" --ops "$OPS" --churn "$churn" \
      --image-name "$name" --filesystem "$FS" --truth "$OUT/$name.truth.json" $compressed_flag
    unmount_fs
    dd if="/dev/$MTD" of="$OUT/$name" bs=1M status=none
    echo "  dumped $name"
  done
done

echo
echo "Done. Score the images with:"
echo "  python3 tools/run_benchmark.py --skip-synthetic --images $OUT --out bench_results_nand"
echo "Unload the simulator afterwards with: sudo rmmod ubifs ubi jffs2 nandsim"
