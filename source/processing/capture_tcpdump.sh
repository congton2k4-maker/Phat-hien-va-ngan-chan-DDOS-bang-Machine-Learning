#!/bin/bash
# capture_tcpdump.sh
# Usage: ./capture_tcpdump.sh <iface> <out_dir> <window_seconds>

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IFACE=${1:-s1-eth1}
OUTDIR=${2:-$PROJECT_ROOT/output/pcap_in}
WIN=${3:-15}
CAP_USER=${CAP_USER:-root}   # user khi drop privilege; để root tránh lỗi ghi
mkdir -p "$OUTDIR"
echo "[CAPTURE] iface=$IFACE outdir=$OUTDIR window=${WIN}s"
# -U unbuffered; -n numeric; -s 0 snaplen; -w with strftime; -G rotate seconds
sudo tcpdump -i "$IFACE" -U -n -s 0 -w "$OUTDIR/pcap-%Y%m%d%H%M%S.pcap" -G "$WIN" -Z "$CAP_USER"
