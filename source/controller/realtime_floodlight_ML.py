#!/usr/bin/env python3
"""Realtime inference for CICFlowMeter CSV -> Floodlight static drop rules.

- Reads CICFlowMeter CSV (realtime output), maps to model schema, imputes/scales using metadata.pkl.
- Predicts via model.pkl; if probability >= threshold, blocks src IP via staticflowpusher.
- src_ip/dst_ip are metadata only, not fed into the model.
"""
import argparse
import json
import logging
import os
import pickle
import sys
import time
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd
import requests

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from machinelearning.feature_schema import FEATURE_NAMES, normalize_cicflowmeter  # type: ignore

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

SWITCHES_ENDPOINT = "/wm/core/controller/switches/json"
STATIC_ENDPOINTS = [
    "/wm/staticflowpusher/json",
    "/wm/staticentrypusher/json",
    "/wm/staticflowentrypusher/json",
]


def load_artifacts(model_path: str, meta_path: Optional[str]) -> Tuple[object, Dict]:
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    if not meta_path:
        meta_path = os.path.join(os.path.dirname(model_path), "metadata.pkl")
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"metadata file not found: {meta_path}")
    with open(meta_path, "rb") as f:
        meta = pickle.load(f)
    return model, meta


def preprocess(df_raw: pd.DataFrame, meta: Dict, drop_active_idle: bool = True) -> Tuple[pd.DataFrame, pd.DataFrame]:
    features, metadata = normalize_cicflowmeter(df_raw, drop_active_idle=drop_active_idle)

    for col in FEATURE_NAMES:
        if col not in features.columns:
            features[col] = np.nan
    features = features[FEATURE_NAMES]

    # Warn if any feature column is entirely missing
    all_nan = [c for c in features.columns if features[c].isna().all()]
    if all_nan:
        logging.warning("Columns are all NaN in realtime data: %s", all_nan)

    for col in features.columns:
        features[col] = pd.to_numeric(features[col], errors="coerce")
    features.replace([np.inf, -np.inf], np.nan, inplace=True)

    medians = meta.get("medians", {})
    features = features.fillna(pd.Series(medians))
    features = features.fillna(0)

    scaler = meta.get("scaler")
    if scaler is not None:
        try:
            features_scaled = pd.DataFrame(scaler.transform(features), columns=features.columns)
        except Exception:
            logging.exception("Scaler.transform failed; using unscaled features")
            features_scaled = features.copy()
    else:
        features_scaled = features.copy()

    return features_scaled, metadata


def predict(model, X: pd.DataFrame) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    return model.predict(X).astype(float)


def fetch_dpids(base_url: str, override: Optional[str]) -> list[str]:
    if override and override.lower() != "auto":
        return [s.strip() for s in override.split(",") if s.strip()]
    try:
        r = requests.get(base_url.rstrip("/") + SWITCHES_ENDPOINT, timeout=5)
        r.raise_for_status()
        data = r.json()
        dpids = []
        for sw in data:
            for k in ("dpid", "switchDPID", "datapathId"):
                if k in sw and sw[k]:
                    dpids.append(sw[k])
                    break
        if not dpids:
            logging.error("Fetched switches but no dpid found; response=%s", r.text[:200])
        return dpids
    except Exception:
        logging.exception("Failed to fetch DPIDs from Floodlight")
        return []


def find_static_endpoint(base_url: str) -> str:
    for ep in STATIC_ENDPOINTS:
        try:
            r = requests.get(base_url.rstrip("/") + ep, timeout=3)
            if r.status_code in (200, 404, 405, 501):
                logging.info("Using static flow endpoint: %s", ep)
                return ep
        except Exception:
            continue
    return STATIC_ENDPOINTS[0]


def block_ip(base_url: str, ip: str, switches: list[str], priority: int = 50000) -> bool:
    ok_any = False
    endpoint = find_static_endpoint(base_url)
    for sw in switches:
        name = f"block-{sw.replace(':', '')}-{ip.replace('.', '_')}"
        payload = {
            "switch": sw,
            "name": name,
            "priority": str(priority),
            "eth_type": "0x0800",
            "ipv4_src": f"{ip}/32",
            "active": "true",
            "actions": "",
        }
        try:
            r = requests.post(base_url.rstrip("/") + endpoint, json=payload, timeout=10)
            if r.status_code == 200:
                logging.info("Block %s on %s -> %s", ip, sw, r.status_code)
                ok_any = True
            else:
                logging.error("Block %s on %s failed: %s body=%s", ip, sw, r.status_code, r.text[:200])
        except requests.exceptions.ReadTimeout:
            logging.error("Block %s on %s timed out", ip, sw)
        except Exception:
            logging.exception("Failed to block %s on %s", ip, sw)
    return ok_any


def run_loop(
    model,
    meta: Dict,
    csv_path: str,
    base_url: str,
    threshold: Optional[float],
    interval: int,
    cooldown: int,
    once: bool,
    always_read: bool,
    switch_arg: str,
):
    seen_block_until: Dict[str, float] = {}
    saved_th = meta.get("threshold", None)
    eff_th = threshold if threshold is not None else (saved_th if saved_th is not None else 0.5)

    logging.info("Realtime inference start: csv=%s threshold=%.3f interval=%ss", csv_path, eff_th, interval)

    last_mtime = 0.0
    while True:
        try:
            if not os.path.exists(csv_path):
                logging.info("CSV not found, sleep %ss", interval)
                time.sleep(interval)
                if once:
                    return
                continue

            mtime = os.path.getmtime(csv_path)
            if (mtime == last_mtime) and (not always_read) and (not once):
                time.sleep(interval)
                continue
            last_mtime = mtime

            df_raw = pd.read_csv(csv_path)
            if df_raw.empty:
                time.sleep(interval)
                if once:
                    return
                continue

            X, meta_cols = preprocess(df_raw, meta, drop_active_idle=True)
            proba = predict(model, X)
            df_pred = meta_cols.copy()
            df_pred["_proba"] = proba

            n_rows = len(df_pred)
            n_alert = 0
            pmax = float(proba.max()) if len(proba) else 0.0
            pmean = float(proba.mean()) if len(proba) else 0.0
            now = time.time()
            dpids = fetch_dpids(base_url, switch_arg)
            if not dpids:
                logging.error("No switches found; will retry after sleep")
            for _, row in df_pred.iterrows():
                src = str(row.get("src_ip", "")).strip()
                dst = str(row.get("dst_ip", "")).strip()
                p = float(row["_proba"])
                if not src:
                    continue
                if p >= eff_th:
                    n_alert += 1
                    until = seen_block_until.get(src, 0)
                    if now >= until:
                        if dpids and block_ip(base_url, src, dpids):
                            seen_block_until[src] = now + cooldown
                            logging.info("Attack detected: src=%s dst=%s proba=%.3f", src, dst, p)

            logging.info("Polled %s rows, alerts=%s (threshold=%.3f, pmax=%.3f, pmean=%.3f)", n_rows, n_alert, eff_th, pmax, pmean)

            if once:
                return
            time.sleep(interval)

        except Exception:
            logging.exception("Error in loop; sleep %ss", interval)
            time.sleep(interval)
            if once:
                return


def parse_args():
    ap = argparse.ArgumentParser(description="Realtime CICFlowMeter ML -> Floodlight dropper")
    ap.add_argument("--model", default="model.pkl")
    ap.add_argument("--meta", default=None, help="Path to metadata.pkl (default: alongside model)")
    ap.add_argument("--csv", default="output/final_csv/Predict.csv", help="CICFlowMeter merged CSV (pcap_processor output)")
    ap.add_argument("--floodlight", default="http://127.0.0.1:8080")
    ap.add_argument("--threshold", type=float, default=None, help="Override threshold (default: metadata or 0.5)")
    ap.add_argument("--interval", type=int, default=2, help="Seconds between polls")
    ap.add_argument("--cooldown", type=int, default=300, help="Seconds to skip re-blocking same src IP")
    ap.add_argument("--once", action="store_true", help="Run one pass and exit")
    ap.add_argument("--always-read", action="store_true", help="Read CSV every interval even if mtime unchanged")
    ap.add_argument("--switch", default="auto", help="DPID(s) comma-separated; 'auto' to fetch from Floodlight")
    return ap.parse_args()


def main():
    args = parse_args()
    model, meta = load_artifacts(args.model, args.meta)
    run_loop(model, meta, args.csv, args.floodlight, args.threshold, args.interval,
             args.cooldown, args.once, args.always_read, args.switch)


if __name__ == "__main__":
    main()
