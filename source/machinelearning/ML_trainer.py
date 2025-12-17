import argparse
import logging
import os
import pickle
from typing import Dict, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from sklearn.metrics import auc as sk_auc
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler

from feature_schema import FEATURE_NAMES, normalize_cicflowmeter

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")


BENIGN_LABELS = {"benign", "normal", "normal traffic", "clean"}


def load_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path, sep=",|\t", engine="python")


def make_labels(df: pd.DataFrame) -> Tuple[pd.Series, Dict[str, int]]:
    if "Attack Type" in df.columns:
        raw = df["Attack Type"].astype(str)
    elif "Label" in df.columns:
        raw = df["Label"].astype(str)
    else:
        raise ValueError("CSV missing label column ('Attack Type' or 'Label')")

    raw_lower = raw.str.strip().str.lower()
    y = raw_lower.apply(lambda s: 0 if s in BENIGN_LABELS else 1)

    classes = sorted(raw_lower.unique())
    class_mapping = {c: int(0 if c in BENIGN_LABELS else 1) for c in classes}
    return y, class_mapping


def preprocess_features(df_raw: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, float], StandardScaler]:
    features, metadata = normalize_cicflowmeter(df_raw, drop_active_idle=True)

    for col in features.columns:
        features[col] = pd.to_numeric(features[col], errors="coerce")

    features.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Warn columns that are all NaN
    all_nan = [c for c in features.columns if features[c].isna().all()]
    if all_nan:
        logging.warning("Columns are all NaN after parsing: %s", all_nan)

    medians = features.median().to_dict()
    features = features.fillna(medians)
    # still NaN? fill with 0 as fallback
    features = features.fillna(0)

    scaler = StandardScaler()
    features_scaled = pd.DataFrame(
        scaler.fit_transform(features), columns=features.columns
    )

    return features_scaled, metadata, medians, scaler


def train_model(X: pd.DataFrame, y: pd.Series) -> Tuple[CalibratedClassifierCV, float]:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    rf_params = dict(n_estimators=300, max_depth=20, random_state=42, n_jobs=-1)

    try:
        cv = cross_val_score(RandomForestClassifier(**rf_params), X, y, cv=5, scoring="roc_auc", n_jobs=-1)
        logging.info("CV ROC AUC (5-fold): mean=%.4f std=%.4f", cv.mean(), cv.std())
    except Exception:
        logging.exception("Cross-validation failed")

    clf = CalibratedClassifierCV(RandomForestClassifier(**rf_params), cv=5)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    auc_val = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    logging.info("Accuracy: %.4f", acc)
    logging.info("AUC: %.4f", auc_val)
    logging.info("Confusion Matrix:\n%s", cm)
    logging.info("Classification Report:\n%s", classification_report(y_test, y_pred))

    try:
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        roc_auc = sk_auc(fpr, tpr)
        plt.figure()
        plt.plot(fpr, tpr, label=f"AUC={roc_auc:.4f}")
        plt.plot([0, 1], [0, 1], "--", color="gray")
        plt.xlabel("FPR")
        plt.ylabel("TPR")
        plt.title("ROC Curve")
        plt.legend()
        plt.savefig("model_eval_roc.png", dpi=150)
        plt.close()

        precision, recall, _ = precision_recall_curve(y_test, y_proba)
        pr_auc = sk_auc(recall, precision)
        plt.figure()
        plt.plot(recall, precision, label=f"AUPR={pr_auc:.4f}")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.title("Precision-Recall")
        plt.legend()
        plt.savefig("model_eval_pr.png", dpi=150)
        plt.close()

        disp = ConfusionMatrixDisplay(confusion_matrix=cm)
        disp.plot(cmap="Blues")
        plt.title("Confusion Matrix")
        plt.savefig("model_eval_cm.png", dpi=150)
        plt.close()
        logging.info("Saved plots: model_eval_{roc,pr,cm}.png")
    except Exception:
        logging.exception("Failed to generate evaluation plots")

    # Threshold: user requested fixed 0.5
    threshold = 0.5
    return clf, threshold


def compute_feature_importances(X: pd.DataFrame, y: pd.Series, path: str = "feature_importances.csv") -> None:
    rf = RandomForestClassifier(n_estimators=300, max_depth=20, random_state=42, n_jobs=-1)
    rf.fit(X, y)
    imp = sorted(zip(X.columns, rf.feature_importances_), key=lambda x: x[1], reverse=True)
    pd.DataFrame(imp, columns=["feature", "importance"]).to_csv(path, index=False)
    logging.info("Saved feature importances to %s", path)


def save_artifacts(model, scaler, medians, threshold, class_mapping, model_path, meta_path):
    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    meta = {
        "feature_names": FEATURE_NAMES,
        "medians": medians,
        "scaler": scaler,
        "threshold": threshold,
        "class_mapping": class_mapping,
    }

    with open(meta_path, "wb") as f:
        pickle.dump(meta, f)

    logging.info("Saved model to %s", model_path)
    logging.info("Saved metadata to %s", meta_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="CICFlowMeter CSV (CICIDS2017 subset)")
    parser.add_argument("--out_model", default="model.pkl")
    parser.add_argument("--out_meta", default="metadata.pkl")
    parser.add_argument("--out_feat_imp", default="feature_importances.csv")
    args = parser.parse_args()

    df_raw = load_csv(args.csv)

    y, class_mapping = make_labels(df_raw)
    X_scaled, _, medians, scaler = preprocess_features(df_raw)

    model, threshold = train_model(X_scaled, y)

    try:
        compute_feature_importances(X_scaled, y, args.out_feat_imp)
    except Exception:
        logging.exception("Failed to compute feature importances")

    save_artifacts(model, scaler, medians, threshold, class_mapping, args.out_model, args.out_meta)

    logging.info("Training complete. ACC/AUC logged above. Threshold fixed at %.2f", threshold)


if __name__ == "__main__":
    main()
