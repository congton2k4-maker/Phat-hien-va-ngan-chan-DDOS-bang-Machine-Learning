# ml_to_floodlight_fixed.py

from __future__ import annotations
import argparse, json, logging, os, pickle, threading, time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
import requests
import ipaddress
from collections import deque, defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

STATIC_ENDPOINTS = [
    '/wm/staticflowpusher/json',
    '/wm/staticentrypusher/json',
    '/wm/staticflowentrypusher/json',
]

def find_static_endpoint(base_url: str) -> Optional[str]:
    for ep in STATIC_ENDPOINTS:
        url = base_url.rstrip('/') + ep
        try:
            r = requests.get(url, timeout=2)
            if r.status_code in (200, 404, 405, 501):
                logging.info('Using static flow endpoint: %s', ep)
                return ep
        except Exception:
            continue
    return None

def load_model(model_path: str):
    logging.info('Loading model from %s', model_path)
    if not os.path.exists(model_path):
        raise FileNotFoundError(model_path)
    with open(model_path, 'rb') as fh:
        obj = pickle.load(fh)

    # Try to load metadata.pkl next to model
    meta = None
    meta_path = os.path.join(os.path.dirname(model_path), 'metadata.pkl')
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'rb') as mf:
                meta = pickle.load(mf)
        except Exception:
            logging.exception('Failed to load metadata from %s', meta_path)

    # obj might be a raw model or a dict containing model + meta
    if isinstance(obj, dict):
        model = obj.get('model')
        if meta is None:
            meta = obj
    else:
        model = obj

    return model, meta

def build_feature_matrix(df: pd.DataFrame, feature_names: Optional[List[str]] = None) -> Tuple[np.ndarray, List[str]]:
    if feature_names:
        missing = [c for c in feature_names if c not in df.columns]
        if missing:
            raise RuntimeError(f'Model expects features not in CSV: {missing}')
        X = df[feature_names].copy()
        return X.values.astype('float64'), feature_names
    drop_cols = ['timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst', 'label']
    cols = [c for c in df.columns if c not in drop_cols]
    numeric = df[cols].select_dtypes(include=[np.number]).columns.tolist()
    if not numeric:
        candidate = [c for c in df.columns if c not in drop_cols]
        X = df[candidate].apply(pd.to_numeric, errors='coerce').fillna(0.0)
        return X.values.astype('float64'), candidate
    X = df[numeric].copy()
    return X.values.astype('float64'), numeric

def push_drop(base_url: str, endpoint: str, switch: str, name: str, match_dict: Dict[str, str], priority: int = 200):
    url = base_url.rstrip('/') + endpoint
    payload = {'switch': switch, 'name': name, 'priority': str(priority), 'active': 'true', 'actions': ''}
    for k, v in match_dict.items():
        payload[k] = v
    try:
        r = requests.post(url, json=payload, timeout=5)
        logging.info('Push flow %s -> status %s', name, r.status_code)
        return r.status_code, r.text
    except Exception as e:
        logging.exception('Failed to push flow %s: %s', name, e)
        return None, str(e)

def delete_flow(base_url: str, endpoint: str, switch: str, name: str):
    url = base_url.rstrip('/') + endpoint
    payload = {'switch': switch, 'name': name}
    try:
        r = requests.delete(url, json=payload, timeout=5)
        logging.info('Delete flow %s -> status %s', name, r.status_code)
        return r.status_code, r.text
    except Exception as e:
        logging.exception('Failed to delete flow %s: %s', name, e)
        return None, str(e)

def get_switches(base_url: str) -> List[str]:
    url = base_url.rstrip('/') + '/wm/core/controller/switches/json'
    try:
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            data = r.json()
            dpids = set()
            for s in data:
                if isinstance(s, dict):
                    for key in ('switchDPID','switchDPid','switchDpid','dpid','id','switch'):
                        v = s.get(key)
                        if v: dpids.add(str(v))
                elif isinstance(s, str):
                    dpids.add(s)
            dpids_list = sorted(dpids)
            logging.info('Found %d switches: %s', len(dpids_list), dpids_list)
            return dpids_list
    except Exception:
        pass
    return []

def schedule_delete(base_url: str, endpoint: str, switch: str, name: str, timeout: int):
    t = threading.Timer(timeout, lambda: delete_flow(base_url, endpoint, switch, name))
    t.daemon = True
    t.start()

def save_blocked(blocked: Dict, path: str = 'blocked_rules.json'):
    try:
        with open(path, 'w') as fh:
            json.dump(blocked, fh, indent=2)
    except Exception:
        logging.exception('Could not write blocked rules file')

def int_to_dpid_hex(dpid_int_val: int) -> Optional[str]:
    try:
        ival = int(dpid_int_val)
        hex16 = format(ival, '016x')
        return ':'.join(hex16[i:i+2] for i in range(0, 16, 2))
    except Exception:
        return None

def derive_dt_features(df: pd.DataFrame) -> pd.DataFrame:
    # Map realtime CSV columns into DT.py feature space
    out = df.copy()
    # Coerce numeric basics
    for c in ['flow_duration_sec','flow_duration_nsec','packet_count','byte_count',
              'packet_count_per_second','byte_count_per_second','packet_count_per_nsecond',
              'byte_count_per_nsecond','idle_timeout','hard_timeout','flags','ip_proto','tp_src','tp_dst']:
        if c in out.columns:
            out[c] = pd.to_numeric(out[c], errors='coerce').fillna(0)

    out['flow_duration'] = out.get('flow_duration_sec', 0.0) + out.get('flow_duration_nsec', 0.0)/1e9
    # Fallback rates if zero
    def _fallback_rate(num, den):
        num = pd.to_numeric(num, errors='coerce')
        den = pd.to_numeric(den, errors='coerce').replace(0, np.nan)
        return num.divide(den).fillna(0)

    if 'packet_count_per_second' in out.columns:
        out['flow_pkts_per_s'] = out['packet_count_per_second'].replace(0, np.nan)
        out['flow_pkts_per_s'] = out['flow_pkts_per_s'].fillna(_fallback_rate(out.get('packet_count', 0), out['flow_duration']))
        out['flow_pkts_per_s'] = out['flow_pkts_per_s'].fillna(0)
    else:
        out['flow_pkts_per_s'] = _fallback_rate(out.get('packet_count', 0), out['flow_duration'])

    if 'byte_count_per_second' in out.columns:
        out['flow_bytes_per_s'] = out['byte_count_per_second'].replace(0, np.nan)
        out['flow_bytes_per_s'] = out['flow_bytes_per_s'].fillna(_fallback_rate(out.get('byte_count', 0), out['flow_duration']))
        out['flow_bytes_per_s'] = out['flow_bytes_per_s'].fillna(0)
    else:
        out['flow_bytes_per_s'] = _fallback_rate(out.get('byte_count', 0), out['flow_duration'])

    out['avg_pkt_size'] = (out.get('byte_count', 0) / out.get('packet_count', 1).replace(0, np.nan)).replace([np.inf, -np.inf], 0).fillna(0)

    out['src_port'] = pd.to_numeric(out.get('tp_src', 0), errors='coerce').fillna(0).astype(int)
    out['dst_port'] = pd.to_numeric(out.get('tp_dst', 0), errors='coerce').fillna(0).astype(int)
    out['is_tcp'] = (out.get('ip_proto', 0) == 6).astype(int)
    out['is_udp'] = (out.get('ip_proto', 0) == 17).astype(int)
    out['is_icmp'] = (out.get('ip_proto', 0) == 1).astype(int)
    return out

def run_loop(model, meta, predict_file: str, base_url: str, threshold: float, timeout: int, interval: int, endpoint: str,
             required_hits: int = 3, detect_window: float = 10.0, cooldown: int = 300, monitored_net: str = '10.0.0.0/24', once: bool = False,
             port_fallback_count: int = 0, port_to_block: int = 80, http_ports: Optional[List[int]] = None, block_per_victim: bool = True,
             min_flows: int = 5, min_total_bytes: int = 10000, min_avg_pkt_rate: float = 200.0, grace_seconds: int = 5):

    blocked_rules = {}
    recent_hits = defaultdict(lambda: deque())
    recent_blocked = {}
    first_seen = {}

    try:
        monitored_net_obj = ipaddress.ip_network(monitored_net)
    except Exception:
        monitored_net_obj = None

    int_to_dpid = lambda raw: int_to_dpid_hex(raw) if str(raw).isdigit() else None

    def apply_preprocessing(df: pd.DataFrame, meta: dict):
        # meta expected keys: features, medians, scaler, log_cols
        features = meta.get('features', [])
        medians = meta.get('medians', {})
        scaler = meta.get('scaler')
        log_cols = meta.get('log_cols', [])

        # ensure all feature columns exist
        for c in features:
            if c not in df.columns:
                df[c] = np.nan

        # coerce to numeric and fill medians
        for c in features:
            df[c] = pd.to_numeric(df[c], errors='coerce')
            df[c] = df[c].fillna(medians.get(c, 0.0))

        # apply log1p for columns remembered during training
        for c in log_cols:
            if c in features:
                vals = df[c].astype(float)
                df[c] = np.log1p(np.maximum(vals, 0.0))

        # build DataFrame of features (preserve column names)
        X_df = df[features].astype(float).copy()

        # apply scaler if present, keep DataFrame with same columns
        if scaler is not None:
            try:
                X_scaled = scaler.transform(X_df)
                if isinstance(X_scaled, pd.DataFrame):
                    X_df_scaled = X_scaled
                else:
                    X_df_scaled = pd.DataFrame(X_scaled, columns=features, index=X_df.index)
            except Exception:
                logging.exception('Scaler.transform failed; using unscaled features')
                X_df_scaled = X_df
        else:
            X_df_scaled = X_df

        return X_df_scaled, features

    while True:
        try:
            if os.path.exists(predict_file):
                df = pd.read_csv(predict_file)
            else:
                fallback = os.path.join(os.path.dirname(predict_file), 'FlowStatsfile.csv')
                if os.path.exists(fallback):
                    df = pd.read_csv(fallback)
                else:
                    logging.info('No CSV found; sleeping')
                    time.sleep(interval)
                    continue

            df.columns = [c.strip() for c in df.columns]

            # Time window filter: only consider last detect_window seconds
            if 'timestamp' in df.columns:
                try:
                    ts = pd.to_datetime(df['timestamp'], errors='coerce')
                    now = pd.Timestamp.utcnow()
                    df = df[ts >= (now - pd.Timedelta(seconds=detect_window))]
                except Exception:
                    pass

            # initialize saved threshold from metadata if available
            saved_threshold = None

            # Prepare feature matrix using saved metadata when available
            if meta and isinstance(meta, dict) and meta.get('features'):
                # derive DT features from base CSV, then apply meta transforms
                df_dt = derive_dt_features(df)
                X_df, feat_names = apply_preprocessing(df_dt, meta)
                saved_threshold = meta.get('threshold', None)
            else:
                # If meta is a plain list (older code), try to use it directly
                if isinstance(meta, list):
                    try:
                        X_vals = derive_dt_features(df)[meta].astype(float).values
                        feat_names = meta
                        X_df = pd.DataFrame(X_vals, columns=feat_names)
                    except Exception:
                        X_vals, feat_names = build_feature_matrix(derive_dt_features(df), None)
                        X_df = pd.DataFrame(X_vals, columns=feat_names)
                else:
                    X_vals, feat_names = build_feature_matrix(derive_dt_features(df), None)
                    X_df = pd.DataFrame(X_vals, columns=feat_names)

            # Predict using DataFrame preserving feature names (avoids sklearn warnings)
            try:
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(X_df)[:,1]
                else:
                    proba = model.predict(X_df).astype(float)
            except Exception:
                logging.exception('Model prediction with DataFrame failed; retrying with numpy array')
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(X_df.values)[:,1]
                else:
                    proba = model.predict(X_df.values).astype(float)

            eff_threshold = saved_threshold if (saved_threshold is not None and threshold is None) else threshold
            eff_threshold = eff_threshold or 0.5
            logging.info('Computed probabilities %d rows (threshold=%.3f)', len(proba), eff_threshold)

            # Filter HTTP (accept proto==6, or unknown(-1) with HTTP dst port)
            if http_ports is None:
                http_ports = [80, 8080]
            proto_series = pd.to_numeric(df.get('ip_proto', -1), errors='coerce').fillna(-1)
            dst_port_series = pd.to_numeric(df.get('tp_dst', 0), errors='coerce').fillna(0).astype(int)
            df['_is_http'] = ((proto_series == 6) | ((proto_series == -1) & dst_port_series.isin(http_ports))) & dst_port_series.isin(http_ports)
            http_count = int(df['_is_http'].sum())
            logging.info('HTTP candidate flows in window: %d', http_count)

            # Attach probabilities to df for grouping-based gating
            df = df.copy()
            df['_pred_proba'] = proba

            # Build candidate indices only for groups that satisfy gating thresholds
            candidates = defaultdict(list)
            df_http = df[df['_is_http']].copy()
            if not df_http.empty:
                # Ensure numeric fields
                df_http['byte_count'] = pd.to_numeric(df_http.get('byte_count', 0), errors='coerce').fillna(0).astype(float)
                df_http['packet_count_per_second'] = pd.to_numeric(df_http.get('packet_count_per_second', 0), errors='coerce').fillna(0).astype(float)

                group_keys = ['ip_src'] + (['ip_dst'] if block_per_victim else [])
                now_epoch = time.time()
                for keys, g in df_http.groupby(group_keys, dropna=False):
                    if not isinstance(keys, tuple):
                        keys = (keys,)
                    src = str(keys[0]) if len(keys) > 0 else ''
                    victim = str(keys[1]) if (block_per_victim and len(keys) > 1) else None
                    if not src:
                        continue

                    key_id = (src, victim)
                    # Grace period for new sources
                    if key_id not in first_seen:
                        first_seen[key_id] = now_epoch
                    if now_epoch - first_seen[key_id] < grace_seconds:
                        continue

                    total_flows = int(len(g))
                    total_bytes = float(g['byte_count'].sum())
                    avg_pkt_rate = float(g['packet_count_per_second'].mean())

                    if total_flows < min_flows or total_bytes < min_total_bytes or avg_pkt_rate < min_avg_pkt_rate:
                        continue

                    # Add indices where proba exceeds threshold
                    idxs = g.index[(g['_pred_proba'] >= eff_threshold)].tolist()
                    if idxs:
                        candidates[(src, victim)].extend(idxs)

            floodlight_dpids = set(get_switches(base_url))
            now = time.time()
            for (src, victim), indices in candidates.items():
                if monitored_net_obj:
                    try:
                        ip_obj = ipaddress.ip_address(src)
                        if ip_obj not in monitored_net_obj:
                            continue
                    except: continue

                key_hits = (src, victim)
                q = recent_hits[key_hits]
                for _ in indices: q.append(now)
                while q and (now - q[0] > detect_window): q.popleft()
                if key_hits in recent_blocked and now < recent_blocked[key_hits]:
                    continue
                if len(q) < required_hits: continue

                chosen_switch = None
                try:
                    row0 = df.iloc[indices[0]]
                    raw_dpid = row0.get('datapath_id') or row0.get('dpid') or row0.get('switch')
                    mapped = None
                    if pd.notna(raw_dpid):
                        mapped = int_to_dpid_hex(int(raw_dpid)) if str(raw_dpid).isdigit() else str(raw_dpid)
                    if mapped in floodlight_dpids: chosen_switch = mapped
                    elif raw_dpid in floodlight_dpids: chosen_switch = str(raw_dpid)
                except: pass
                if not chosen_switch and floodlight_dpids: chosen_switch = sorted(floodlight_dpids)[0]
                if not chosen_switch: continue

                name = f'block_http_{src.replace(".","_")}_{(victim or "any").replace(".","_")}_{int(now)}'
                match = {'eth_type':'0x0800','ipv4_src':src, 'ip_proto':'0x06'}
                # choose a port to pin (mode of tp_dst in this group), default 80
                try:
                    dst_port_mode = int(pd.to_numeric(df.loc[indices, 'tp_dst'], errors='coerce').mode().iat[0])
                except Exception:
                    dst_port_mode = 80
                match['tcp_dst'] = str(dst_port_mode)
                if block_per_victim and victim:
                    match['ipv4_dst'] = victim
                status,_ = push_drop(base_url, endpoint, chosen_switch, name, match)
                if status:
                    added = datetime.utcnow().isoformat()+'Z'
                    blocked_rules[name] = {
                        'switch': chosen_switch,
                        'src_ip': src,
                        'dst_ip': victim,
                        'tcp_dst': dst_port_mode,
                        'added': added,
                        'expires': datetime.utcnow().timestamp()+timeout
                    }
                    save_blocked(blocked_rules)
                    schedule_delete(base_url, endpoint, chosen_switch, name, timeout)
                    recent_blocked[key_hits] = now+cooldown

            if once: return
            time.sleep(interval)

        except Exception:
            logging.exception('Error in main loop; retrying')
            time.sleep(interval)

def parse_args():
    p = argparse.ArgumentParser(description='ML -> Floodlight static flow pusher')
    p.add_argument('--model', default='../machinelearning/model.pkl')
    p.add_argument('--predict-file', default='../output/PredictFlowStatsfile.csv')
    p.add_argument('--floodlight', default='http://127.0.0.1:8080')
    p.add_argument('--threshold', type=float, default=None, help='Override saved threshold; leave empty to use metadata')
    p.add_argument('--timeout', type=int, default=180)
    p.add_argument('--interval', type=int, default=5)
    p.add_argument('--required-hits', type=int, default=3)
    p.add_argument('--detect-window', type=float, default=10.0)
    p.add_argument('--cooldown', type=int, default=300)
    p.add_argument('--monitored-net', default='10.0.0.0/24')
    p.add_argument('--port-fallback-count', type=int, default=0, help='Number of distinct sources to same dst to trigger port block')
    p.add_argument('--port-to-block', type=int, default=80, help='TCP destination port to block when fallback triggers')
    p.add_argument('--http-ports', type=int, nargs='*', default=[80, 8080])
    p.add_argument('--block-per-victim', action='store_true', help='Match ipv4_dst to scope block to a victim')
    p.add_argument('--once', action='store_true')
    p.add_argument('--min-flows', type=int, default=5, help='Minimum HTTP flows per (src[,dst]) in window to consider a hit')
    p.add_argument('--min-total-bytes', type=int, default=10000, help='Minimum total bytes per (src[,dst]) in window to consider a hit')
    p.add_argument('--min-avg-pkt-rate', type=float, default=200.0, help='Minimum average packets/sec per (src[,dst]) in window to consider a hit')
    p.add_argument('--grace-seconds', type=int, default=5, help='Skip blocking for a source for this many seconds after first seen')
    return p.parse_args()

def main():
    args = parse_args()
    model, meta = load_model(args.model)
    endpoint = find_static_endpoint(args.floodlight) or STATIC_ENDPOINTS[0]
    run_loop(model, meta, args.predict_file, args.floodlight, args.threshold, args.timeout, args.interval,
             endpoint, required_hits=args.required_hits, detect_window=args.detect_window, cooldown=args.cooldown, monitored_net=args.monitored_net, once=args.once,
             port_fallback_count=args.port_fallback_count, port_to_block=args.port_to_block,
             http_ports=args.http_ports, block_per_victim=args.block_per_victim,
             min_flows=args.min_flows, min_total_bytes=args.min_total_bytes,
             min_avg_pkt_rate=args.min_avg_pkt_rate, grace_seconds=args.grace_seconds)

if __name__=='__main__':
    main()
