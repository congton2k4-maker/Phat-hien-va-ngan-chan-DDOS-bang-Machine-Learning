"""Feature schema and helpers for CICFlowMeter-based training/inference.

- FEATURE_NAMES: ordered list of model input columns (Active/Idle removed).
- CICFLOWMETER_MAP: rename map from raw CICFlowMeter headers to our schema.
- META_COLS: metadata columns kept for actions (not fed to model).
- normalize_cicflowmeter: rename, drop unused columns, fill missing features, split features/metadata.
"""
from __future__ import annotations

from typing import Tuple

import numpy as np
import pandas as pd

# Ordered feature list for the model (no Active/Idle, no IP metadata)
FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Packet Length Std",
    "Packet Length Max",
    "Packet Length Min",
    "ACK Flag Count",
    "FIN Flag Count",
    "PSH Flag Count",
]

# Columns to drop outright (noisy/unstable for CICFlowMeter in this setup)
ACTIVE_IDLE_COLS = [
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# Metadata columns used for actions (do NOT feed into the model)
META_COLS = ["src_ip", "dst_ip", "dst_port", "protocol"]

# Raw CICFlowMeter headers -> our schema / metadata
CICFLOWMETER_MAP = {
    # Port and durations
    "Destination Port": "Destination Port",
    "Dst Port": "Destination Port",
    "Flow Duration": "Flow Duration",
    # Packet counts/lengths (handle singular/plural variants)
    "Total Fwd Packets": "Total Fwd Packets",
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Bwd Packets",  # not used by model but kept if present
    "Total Length of Fwd Packets": "Total Length of Fwd Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packets": "Total Length of Bwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    "Total length of Bwd packets": "Total Length of Bwd Packets",
    "Total length of BwD packets": "Total Length of Bwd Packets",
    "Total length of Bwd Packets": "Total Length of Bwd Packets",
    "Total length of Bwd Packets ": "Total Length of Bwd Packets",
    "Total Length of Bwd Packets ": "Total Length of Bwd Packets",
    "Flow Bytes/s": "Flow Bytes/s",
    "Flow Packets/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Total": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Total": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd Packet Length Max": "Fwd Packet Length Max",
    "Fwd Packet Length Min": "Fwd Packet Length Min",
    "Fwd Packet Length Mean": "Fwd Packet Length Mean",
    "Fwd Packet Length Std": "Fwd Packet Length Std",
    "Bwd Packet Length Max": "Bwd Packet Length Max",
    "Bwd Packet Length Min": "Bwd Packet Length Min",
    "Bwd Packet Length Mean": "Bwd Packet Length Mean",
    "Bwd Packet Length Std": "Bwd Packet Length Std",
    # Packet length aggregations (alias variants)
    "Packet Length Min": "Packet Length Min",
    "Packet Length Max": "Packet Length Max",
    "Min Packet Length": "Packet Length Min",
    "Max Packet Length": "Packet Length Max",
    "Packet Length Mean": "Packet Length Mean",
    "Packet Length Std": "Packet Length Std",
    "Packet Length Variance": "Packet Length Variance",
    "FIN Flag Count": "FIN Flag Count",
    "SYN Flag Count": "SYN Flag Count",
    "RST Flag Count": "RST Flag Count",
    "PSH Flag Count": "PSH Flag Count",
    "ACK Flag Count": "ACK Flag Count",
    "URG Flag Count": "URG Flag Count",
    "CWR Flag Count": "CWR Flag Count",
    "ECE Flag Count": "ECE Flag Count",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Length": "Fwd Header Length",
    "Bwd Header Length": "Bwd Header Length",
    "Fwd Packets/s": "Fwd Packets/s",
    "Bwd Packets/s": "Bwd Packets/s",
    "Down/Up Ratio": "Down/Up Ratio",
    "Average Packet Size": "Average Packet Size",
    "Fwd Segment Size Avg": "Fwd Segment Size Avg",
    "Bwd Segment Size Avg": "Bwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg": "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg": "Fwd Packet/Bulk Avg",
    "Fwd Bulk Rate Avg": "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg": "Bwd Bytes/Bulk Avg",
    "Bwd Packet/Bulk Avg": "Bwd Packet/Bulk Avg",
    "Bwd Bulk Rate Avg": "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets": "Subflow Fwd Packets",
    "Subflow Fwd Bytes": "Subflow Fwd Bytes",
    "Subflow Bwd Packets": "Subflow Bwd Packets",
    "Subflow Bwd Bytes": "Subflow Bwd Bytes",
    "FWD Init Win Bytes": "FWD Init Win Bytes",
    "Bwd Init Win Bytes": "Bwd Init Win Bytes",
    "Fwd Act Data Pkts": "Fwd Act Data Pkts",
    "Fwd Seg Size Min": "Fwd Seg Size Min",
    "Label": "Label",
    "Flow ID": "Flow ID",
    "Src IP": "src_ip",
    "Dst IP": "dst_ip",
    "Src Port": "Src Port",
    "Protocol": "protocol",
}


def normalize_cicflowmeter(df: pd.DataFrame, drop_active_idle: bool = True) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Rename/map CICFlowMeter columns, drop noisy Active/Idle fields, and split features vs. metadata.

    Returns
    -------
    features : DataFrame
        Contains FEATURE_NAMES in the correct order (missing columns filled with NaN for later imputation).
    metadata : DataFrame
        Contains src_ip, dst_ip, dst_port, protocol for downstream actions.
    """
    df = df.copy()

    # Rename using the provided map
    df.rename(columns=CICFLOWMETER_MAP, inplace=True)

    # Drop unstable Active/Idle fields if present
    if drop_active_idle:
        df.drop(columns=[c for c in ACTIVE_IDLE_COLS if c in df.columns], inplace=True, errors="ignore")

    # Build metadata frame
    metadata = pd.DataFrame(
        {
            "src_ip": df.get("src_ip"),
            "dst_ip": df.get("dst_ip"),
            "dst_port": df.get("Destination Port"),
            "protocol": df.get("protocol"),
        }
    )

    # Ensure all required feature columns exist; fill missing with NaN for later imputation
    for col in FEATURE_NAMES:
        if col not in df.columns:
            df[col] = np.nan

    # Derive totals if missing but components exist
    if df.get("Total Length of Fwd Packets") is not None and df["Total Length of Fwd Packets"].isna().all():
        total_fwd_pkts = df.get("Total Fwd Packets")
        fwd_pkt_len_mean = df.get("Fwd Packet Length Mean")
        if total_fwd_pkts is not None and fwd_pkt_len_mean is not None:
            try:
                df["Total Length of Fwd Packets"] = pd.to_numeric(total_fwd_pkts, errors="coerce") * pd.to_numeric(
                    fwd_pkt_len_mean, errors="coerce"
                )
            except Exception:
                pass

    features = df[FEATURE_NAMES].copy()

    return features, metadata
