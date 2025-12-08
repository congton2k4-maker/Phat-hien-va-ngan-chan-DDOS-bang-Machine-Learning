#!/usr/bin/env python3
# collect_realtime_traffic_ml.py
# Floodlight 1.2 realtime flow collector -> PredictFlowStatsfile.csv
# No Ryu, no fallback endpoints. Uses /wm/core/switch/all/flow/json.

import os
import csv
import time
import requests
from datetime import datetime

FLOODLIGHT = os.getenv('FLOODLIGHT', 'http://127.0.0.1:8080')
OUTDIR = os.getenv('OUTDIR', 'output')
PRED = os.path.join(OUTDIR, 'PredictFlowStatsfile.csv')
INTERVAL = int(os.getenv('INTERVAL', '5'))
# Optional: rotate when file size exceeds ROTATE_MB (0 disables rotation)
ROTATE_MB = float(os.getenv('ROTATE_MB', '0'))

# Keep previous counters to compute per-second deltas
_prev = {}

CSV_FIELDS = [
    'timestamp','datapath_id','flow_id','ip_src','tp_src','ip_dst','tp_dst','ip_proto',
    'icmp_code','icmp_type','flow_duration_sec','flow_duration_nsec','idle_timeout',
    'hard_timeout','flags','packet_count','byte_count','packet_count_per_second',
    'packet_count_per_nsecond','byte_count_per_second','byte_count_per_nsecond'
]

def dpid_to_int(dpid_str: str) -> int:
    try:
        return int(dpid_str.replace(':', ''), 16)
    except Exception:
        return 0

def safe_int(val, default=0) -> int:
    try:
        if val is None:
            return int(default)
        return int(val)
    except Exception:
        try:
            return int(float(val))
        except Exception:
            return int(default)

def parse_flow(flow: dict, dpid_int: int, ts_iso: str):
    match = flow.get('match', {}) or {}

    eth_type = match.get('eth_type') or match.get('ethType') or match.get('dataLayerType')
    eth_type_s = str(eth_type).lower() if eth_type is not None else ""
    if eth_type_s not in ("0x800", "0x0800", "2048"):
        return None  # only IPv4

    ip_src = match.get('ipv4_src') or match.get('nw_src') or match.get('networkSource')
    ip_dst = match.get('ipv4_dst') or match.get('nw_dst') or match.get('networkDestination')
    if not ip_src or not ip_dst:
        return None
    ip_src = str(ip_src).split('/')[0]
    ip_dst = str(ip_dst).split('/')[0]

    ip_proto = match.get('ip_proto') or match.get('nw_proto') or match.get('ipProto') or match.get('networkProtocol') or match.get('nwProto')
    try:
        ip_proto = int(ip_proto)
    except Exception:
        ip_proto = -1

    tp_src = match.get('tcp_src') or match.get('udp_src') or match.get('transportSource') or 0
    tp_dst = match.get('tcp_dst') or match.get('udp_dst') or match.get('transportDestination') or 0
    tp_src = safe_int(tp_src, 0)
    tp_dst = safe_int(tp_dst, 0)

    icmp_code = -1
    icmp_type = -1
    if ip_proto == 1:
        icmp_code = safe_int(match.get('icmpv4_code') or match.get('icmp_code') or match.get('icmpv4Code'), -1)
        icmp_type = safe_int(match.get('icmpv4_type') or match.get('icmp_type') or match.get('icmpv4Type'), -1)

    duration_sec = safe_int(flow.get('durationSeconds') or flow.get('duration_sec') or flow.get('duration'), 0)
    duration_nsec = safe_int(flow.get('durationNanoseconds') or flow.get('duration_nsec') or flow.get('durationNanoSeconds'), 0)
    idle_timeout = safe_int(flow.get('idleTimeout') or flow.get('idle_timeout'), 0)
    hard_timeout = safe_int(flow.get('hardTimeout') or flow.get('hard_timeout'), 0)
    flags = safe_int(flow.get('flags'), 0)
    packet_count = safe_int(flow.get('packetCount') or flow.get('packet_count') or flow.get('packets'), 0)
    byte_count = safe_int(flow.get('byteCount') or flow.get('byte_count') or flow.get('bytes'), 0)

    flow_id = f"{ip_src}:{tp_src}-{ip_dst}:{tp_dst}-{ip_proto}"

    # per-second deltas using previous snapshot (per flow_id per dpid)
    nowt = time.time()
    prev_key = f"{dpid_int}|{flow_id}"
    prev = _prev.get(prev_key, {'pkts': packet_count, 'bytes': byte_count, 't': nowt})
    dt = max(1e-6, nowt - prev['t'])
    dpkts = max(0, packet_count - prev['pkts'])
    dbytes = max(0, byte_count - prev['bytes'])
    pkt_per_s = dpkts / dt
    byte_per_s = dbytes / dt
    pkt_per_ns = pkt_per_s / 1e9
    byte_per_ns = byte_per_s / 1e9
    _prev[prev_key] = {'pkts': packet_count, 'bytes': byte_count, 't': nowt}

    return {
        'timestamp': ts_iso,
        'datapath_id': dpid_int,
        'flow_id': flow_id,
        'ip_src': ip_src,
        'tp_src': tp_src,
        'ip_dst': ip_dst,
        'tp_dst': tp_dst,
        'ip_proto': ip_proto,
        'icmp_code': icmp_code,
        'icmp_type': icmp_type,
        'flow_duration_sec': duration_sec,
        'flow_duration_nsec': duration_nsec,
        'idle_timeout': idle_timeout,
        'hard_timeout': hard_timeout,
        'flags': flags,
        'packet_count': packet_count,
        'byte_count': byte_count,
        'packet_count_per_second': pkt_per_s,
        'packet_count_per_nsecond': pkt_per_ns,
        'byte_count_per_second': byte_per_s,
        'byte_count_per_nsecond': byte_per_ns,
    }

def collect_once(base_url: str):
    url = base_url.rstrip('/') + '/wm/core/switch/all/flow/json'
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    data = r.json()

    ts_iso = datetime.utcnow().isoformat() + 'Z'
    out_rows = []

    # Expect dict: { dpid: { 'flows': [ ... ] } }
    if isinstance(data, dict):
        for dpid, sw_data in data.items():
            dpid_int = dpid_to_int(dpid)
            flows = []
            if isinstance(sw_data, dict):
                flows = sw_data.get('flows', []) or []
            elif isinstance(sw_data, list):
                flows = sw_data
            for flow in flows:
                row = parse_flow(flow, dpid_int, ts_iso)
                if row:
                    out_rows.append(row)

    return out_rows

def ensure_header(path: str):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    need = not os.path.exists(path) or os.path.getsize(path) == 0
    if need:
        with open(path, 'a', newline='', encoding='utf-8') as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            w.writeheader()

def maybe_rotate(path: str):
    if ROTATE_MB <= 0:
        return
    if os.path.exists(path):
        size_mb = os.path.getsize(path) / (1024*1024)
        if size_mb >= ROTATE_MB:
            ts = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
            new_name = os.path.join(os.path.dirname(path), f"PredictFlowStatsfile-{ts}.csv")
            try:
                os.replace(path, new_name)
                print(f"Rotated {path} -> {new_name}")
            except Exception as ex:
                print(f"[warn] rotate failed: {ex}")

def main():
    print(f"Collector starting (Floodlight) url={FLOODLIGHT}, interval={INTERVAL}s, out={PRED}")
    while True:
        try:
            rows = collect_once(FLOODLIGHT)
            if rows:
                # optional rotation
                maybe_rotate(PRED)
                # ensure header exists once
                ensure_header(PRED)
                # append snapshot rows
                with open(PRED, 'a', newline='', encoding='utf-8') as fh:
                    w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
                    for r in rows:
                        w.writerow(r)
                print(f"{datetime.utcnow().isoformat()} appended {len(rows)} rows -> {PRED}")
            else:
                # Do not overwrite with a single 'timestamp' line; just log.
                print(f"{datetime.utcnow().isoformat()} no IPv4 flows this interval")
        except Exception as ex:
            print(f"[warn] collect error: {ex}")
        time.sleep(INTERVAL)

if __name__ == '__main__':
    main()
