import os
import time
import argparse
import requests
from datetime import datetime
from typing import Any, Dict

OUTPUT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'output'))
OUTPUT_CSV = os.path.join(OUTPUT_DIR, 'FlowStatsfile.csv')

CSV_HEADER = ('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
              'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,'
              'packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,label\n')

def dpid_to_int(dpid_str: str) -> int:
    """Convert Floodlight DPID format (colon-separated hex) to int."""
    try:
        return int(dpid_str.replace(':', ''), 16)
    except Exception:
        return 0

def safe_div(n: Any, d: Any) -> float:
    try:
        d = float(d)
        n = float(n)
        return (n / d) if d > 0 else 0.0
    except Exception:
        return 0.0

def ensure_header():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    need_header = not os.path.exists(OUTPUT_CSV) or os.path.getsize(OUTPUT_CSV) == 0
    if need_header:
        with open(OUTPUT_CSV, 'a+', encoding='utf-8') as f:
            f.write(CSV_HEADER)

def parse_flow(flow: Dict[str, Any], dpid_int: int, timestamp: float, label: int) -> str | None:
    match = flow.get('match', {}) or {}
    print(f"DEBUG_RAW: {match}")
    # Chỉ lấy flow IPv4 có đủ trường
    eth_type = match.get('eth_type') or match.get('ethType') or match.get('dataLayerType')
    eth_type_s = str(eth_type).lower() if eth_type is not None else ""
    if eth_type_s not in ("0x800", "0x0800", '0x0x800', "2048"):
        return None

    ip_src = match.get('ipv4_src') or match.get('nw_src') or match.get('networkSource')
    ip_dst = match.get('ipv4_dst') or match.get('nw_dst') or match.get('networkDestination')
    if not ip_src or not ip_dst:
        return None
    ip_src = str(ip_src).split("/")[0]
    ip_dst = str(ip_dst).split("/")[0]

    ip_proto = match.get('ip_proto') or match.get('nw_proto') or match.get('ipProto') or match.get('networkProtocol') or match.get('nwProto')
    try:
        ip_proto = int(ip_proto)
    except Exception:
        ip_proto = -1

    tp_src = match.get('tcp_src') or match.get('udp_src') or match.get('transportSource') or 0
    tp_dst = match.get('tcp_dst') or match.get('udp_dst') or match.get('transportDestination') or 0
    try:
        tp_src = int(tp_src)
    except Exception:
        tp_src = 0
    try:
        tp_dst = int(tp_dst)
    except Exception:
        tp_dst = 0

    icmp_code = -1
    icmp_type = -1
    if ip_proto == 1:
        try:
            icmp_code = int(match.get('icmpv4_code', match.get('icmp_code', match.get('icmpv4Code', -1))))
        except Exception:
            icmp_code = -1
        try:
            icmp_type = int(match.get('icmpv4_type', match.get('icmp_type', match.get('icmpv4Type', -1))))
        except Exception:
            icmp_type = -1

    # helper to get integer value from multiple possible key names
    def _get_int(obj: Dict[str, Any], *keys, default=0) -> int:
        for k in keys:
            if k in obj and obj[k] is not None:
                try:
                    return int(obj[k])
                except Exception:
                    try:
                        return int(float(obj[k]))
                    except Exception:
                        continue
        return int(default)

    duration_sec = _get_int(flow, 'durationSeconds', 'duration_sec', 'durationSecondsNanoseconds', default=0)
    duration_nsec = _get_int(flow, 'durationNanoseconds', 'duration_nsec', 'durationNanoseconds', default=0)
    idle_timeout = _get_int(flow, 'idleTimeout', 'idle_timeout', default=0)
    hard_timeout = _get_int(flow, 'hardTimeout', 'hard_timeout', default=0)
    flags = _get_int(flow, 'flags', default=0)
    packet_count = _get_int(flow, 'packetCount', 'packet_count', default=0)
    byte_count = _get_int(flow, 'byteCount', 'byte_count', default=0)

    # Bỏ qua flow chưa có traffic
    #if packet_count == 0 and byte_count == 0:
        #return None

    packet_count_per_second = safe_div(packet_count, duration_sec)
    packet_count_per_nsecond = safe_div(packet_count, duration_nsec)
    byte_count_per_second = safe_div(byte_count, duration_sec)
    byte_count_per_nsecond = safe_div(byte_count, duration_nsec)

    # make flow id readable: ip_src:tp_src-ip_dst:tp_dst-proto
    flow_id = f"{ip_src}:{tp_src}-{ip_dst}:{tp_dst}-{ip_proto}"
    
    return (f"{timestamp},{dpid_int},{flow_id},{ip_src},{tp_src},{ip_dst},{tp_dst},{ip_proto},{icmp_code},{icmp_type},"
            f"{duration_sec},{duration_nsec},{idle_timeout},{hard_timeout},{flags},{packet_count},{byte_count},"
            f"{packet_count_per_second},{packet_count_per_nsecond},{byte_count_per_second},{byte_count_per_nsecond},{int(label)}\n")
    
def collect_once(base_url: str, label: int):
    url = base_url.rstrip('/') + '/wm/core/switch/all/flow/json'
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    data = r.json()

    ts = datetime.now().timestamp()
    rows: list[str] = []

    for dpid, sw_data in data.items():
        dpid_int = dpid_to_int(dpid)
        flows = sw_data.get("flows", [])
        for flow in flows:
            print(f"DEBUG_FLOW: {flow}")
            line = parse_flow(flow, dpid_int, ts, label)
            if line:
                rows.append(line)

    if rows:
        with open(OUTPUT_CSV, 'a+', encoding='utf-8') as f:
            for line in rows:
                f.write(line)
        print(f"Appended {len(rows)} flow rows (label={label})")
    else:
        print("No matching IPv4 flows this interval")

def main():
    ap = argparse.ArgumentParser(description='Floodlight FlowStats CSV collector')
    ap.add_argument('--controller', default='http://127.0.0.1:8080', help='Floodlight REST base URL')
    ap.add_argument('--interval', type=int, default=10, help='Polling interval seconds')
    ap.add_argument('--label', type=int, default=0, help='0=normal,1=ddos')
    args = ap.parse_args()

    ensure_header()
    print(f"Collecting from {args.controller} every {args.interval}s, label={args.label}. Ctrl+C to stop.")
    try:
        while True:
            try:
                collect_once(args.controller, args.label)
            except Exception as ex:
                print(f"[warn] collect error: {ex}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print('Collector stopped.')

if __name__ == '__main__':
    main()

#Quang