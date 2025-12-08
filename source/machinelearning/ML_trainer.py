import os
import pickle
import logging
import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)
from sklearn.metrics import roc_curve, precision_recall_curve, auc as sk_auc, ConfusionMatrixDisplay
import os
import pickle
import logging
import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)
from sklearn.metrics import roc_curve, precision_recall_curve, auc as sk_auc, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler

# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s"
)

# ============================================================
# EXPECTED CSV COLUMNS (from collect_training_stats_floodlight.py)
# ============================================================
COLLECTOR_COLUMNS = [
    "timestamp","datapath_id","flow_id","ip_src","tp_src","ip_dst","tp_dst","ip_proto",
    "icmp_code","icmp_type","flow_duration_sec","flow_duration_nsec","idle_timeout",
    "hard_timeout","flags","packet_count","byte_count","packet_count_per_second",
    "packet_count_per_nsecond","byte_count_per_second","byte_count_per_nsecond","label"
]


# ============================================================
# LABEL CLEAN (collector uses numeric label 0/1)
# ============================================================
def clean_label_val(v):
    try:
        return int(v) if (str(v).strip() != "") else 0
    except Exception:
        s = str(v).strip().lower()
        if s in ("normal traffic", "normal", "benign"):
            return 0
        return 1


# ============================================================
# MODEL WRAPPER (adapted to flow-stats schema)
# ============================================================
class FlowModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.features = None
        self.medians = None

    def _build_features(self, df: pd.DataFrame) -> pd.DataFrame:
        # Ensure numeric conversions for raw fields
        for c in ["flow_duration_sec","flow_duration_nsec","packet_count","byte_count",
                  "packet_count_per_second","byte_count_per_second","packet_count_per_nsecond",
                  "byte_count_per_nsecond","idle_timeout","hard_timeout","flags","ip_proto","tp_src","tp_dst"]:
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

        # Flow duration in seconds (float)
        df["flow_duration"] = df.get("flow_duration_sec", 0.0) + df.get("flow_duration_nsec", 0.0) / 1e9
        # Fallback packet/byte rates if not provided
        df["flow_pkts_per_s"] = df["packet_count_per_second"].replace(0, np.nan).fillna(df["packet_count"] / df["flow_duration"].replace(0, np.nan)).fillna(0)
        df["flow_bytes_per_s"] = df["byte_count_per_second"].replace(0, np.nan).fillna(df["byte_count"] / df["flow_duration"].replace(0, np.nan)).fillna(0)
        # packet_count / byte_count
        df["avg_pkt_size"] = (df["byte_count"] / df["packet_count"]).replace([np.inf, -np.inf], 0).fillna(0)

        # Protocol flags
        df["is_tcp"] = (df["ip_proto"] == 6).astype(int)
        df["is_udp"] = (df["ip_proto"] == 17).astype(int)
        df["is_icmp"] = (df["ip_proto"] == 1).astype(int)

        # Destination port (tp_dst) numeric
        df["dst_port"] = pd.to_numeric(df.get("tp_dst", 0), errors="coerce").fillna(0).astype(int)
        df["src_port"] = pd.to_numeric(df.get("tp_src", 0), errors="coerce").fillna(0).astype(int)

        # Basic features list to train on
        feature_cols = [
            "flow_duration",
            "packet_count",
            "byte_count",
            "flow_pkts_per_s",
            "flow_bytes_per_s",
            "packet_count_per_nsecond",
            "byte_count_per_nsecond",
            "idle_timeout",
            "hard_timeout",
            "flags",
            "ip_proto",
            "src_port",
            "dst_port",
            "is_tcp",
            "is_udp",
            "is_icmp",
            "avg_pkt_size",
        ]

        # Ensure all feature cols exist
        for c in feature_cols:
            if c not in df.columns:
                df[c] = 0.0

        return df, feature_cols

    def preprocess_train(self, df: pd.DataFrame):
        # Map label (collector provides numeric 'label' column)
        if "label" in df.columns:
            df["label"] = df["label"].apply(clean_label_val)
        elif "Attack Type" in df.columns:
            df["label"] = df["Attack Type"].apply(lambda s: 0 if str(s).strip().lower() in ("normal","normal traffic","benign") else 1)
        else:
            raise ValueError("No label column found in dataframe")

        # Build derived features
        df, feature_cols = self._build_features(df)

        # Numeric only feature set
        numeric_cols = feature_cols.copy()

        # Convert numeric columns and replace infinities
        for c in numeric_cols:
            df[c] = pd.to_numeric(df[c], errors="coerce")
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

        # Fill medians
        self.medians = df[numeric_cols].median().to_dict()
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())

        # Log1p transform for skewed features
        skew = df[numeric_cols].skew().abs()
        self.log_cols = skew[skew > 1.2].index.tolist()
        for c in self.log_cols:
            # clip negatives to 0 (counts/size/rate should be non-negative)
            df[c] = df[c].clip(lower=0.0)
            df[c] = np.log1p(df[c])

        # Refill any NaNs created
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())

        # Scale
        self.scaler = StandardScaler()
        df[numeric_cols] = self.scaler.fit_transform(df[numeric_cols])

        self.features = numeric_cols
        return df

    def train(self, df: pd.DataFrame):
        df = self.preprocess_train(df)

        X = df[self.features]
        y = df["label"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )

        # RandomForest parameters
        rf_params = dict(n_estimators=300, max_depth=20, random_state=42, n_jobs=-1)

        # Quick cross-validation on the raw RandomForest to detect overfitting/generalization
        try:
            cv_scores = cross_val_score(RandomForestClassifier(**rf_params), X, y, cv=5, scoring='roc_auc', n_jobs=-1)
            logging.info('CV ROC AUC (5-fold): mean=%.4f std=%.4f', cv_scores.mean(), cv_scores.std())
        except Exception:
            logging.exception('Cross-validation failed')

        # Fit a plain RF on the training set to get feature importances
        try:
            rf_simple = RandomForestClassifier(**rf_params)
            rf_simple.fit(X_train, y_train)
            importances = rf_simple.feature_importances_
            feat_imp = sorted(zip(self.features, importances), key=lambda x: x[1], reverse=True)
            # save top importances
            try:
                imp_df = pd.DataFrame(feat_imp, columns=['feature','importance'])
                imp_df.to_csv('feature_importances.csv', index=False)
            except Exception:
                logging.exception('Could not write feature importances')
            logging.info('Top features: %s', feat_imp[:10])
        except Exception:
            logging.exception('Could not compute feature importances')

        # Use CalibratedClassifier so we can get predict_proba stable
        self.model = CalibratedClassifierCV(RandomForestClassifier(**rf_params), cv=5)
        self.model.fit(X_train, y_train)

        # =============== Evaluation ===============
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_proba)
        cm = confusion_matrix(y_test, y_pred)

        logging.info("Accuracy: %.4f", acc)
        logging.info("AUC: %.4f", auc)
        logging.info("Confusion Matrix:\n%s", cm)
        logging.info("Classification Report:\n%s", classification_report(y_test, y_pred))

        # Choose a probability threshold that maximizes F1 on the validation set
        try:
            from sklearn.metrics import f1_score

            best_thr = 0.5
            best_f1 = 0.0
            for thr in np.linspace(0.01, 0.99, 99):
                preds = (y_proba >= thr).astype(int)
                f1 = f1_score(y_test, preds)
                if f1 > best_f1:
                    best_f1 = f1
                    best_thr = float(thr)
            self.threshold = best_thr
            logging.info("Selected threshold=%.3f (F1=%.3f)", self.threshold, best_f1)
        except Exception:
            self.threshold = 0.5

        # =============== Plots: ROC, PR, Confusion Matrix ===============
        try:
            fpr, tpr, _ = roc_curve(y_test, y_proba)
            roc_auc = sk_auc(fpr, tpr)
            plt.figure()
            plt.plot(fpr, tpr, label=f'AUC={roc_auc:.4f}')
            plt.plot([0,1],[0,1],'--',color='gray')
            plt.xlabel('FPR'); plt.ylabel('TPR'); plt.title('ROC Curve'); plt.legend()
            plt.savefig('model_eval_roc.png', dpi=150)
            plt.close()

            precision, recall, _ = precision_recall_curve(y_test, y_proba)
            pr_auc = sk_auc(recall, precision)
            plt.figure()
            plt.plot(recall, precision, label=f'AUPR={pr_auc:.4f}')
            plt.xlabel('Recall'); plt.ylabel('Precision'); plt.title('Precision-Recall'); plt.legend()
            plt.savefig('model_eval_pr.png', dpi=150)
            plt.close()

            disp = ConfusionMatrixDisplay(confusion_matrix=cm)
            disp.plot(cmap='Blues')
            plt.title('Confusion Matrix')
            plt.savefig('model_eval_cm.png', dpi=150)
            plt.close()
            logging.info('Saved plots: model_eval_{roc,pr,cm}.png')
        except Exception:
            logging.exception('Failed to generate evaluation plots')

        return acc, auc

    def save(self, path="model.pkl", meta_path="metadata.pkl"):
        with open(path, "wb") as f:
            pickle.dump(self.model, f)

        meta = {
            "features": self.features,
            "medians": self.medians,
            "scaler": self.scaler,
            "log_cols": getattr(self, 'log_cols', []),
            "threshold": getattr(self, 'threshold', None),
        }

        with open(meta_path, "wb") as f:
            pickle.dump(meta, f)

        logging.info("Saved model to %s", path)
        logging.info("Saved metadata to %s", meta_path)


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="Input CSV file (FlowStatsfile.csv from collector)")
    parser.add_argument("--out_model", default="model.pkl")
    parser.add_argument("--out_meta", default="metadata.pkl")
    args = parser.parse_args()

    # Load CSV
    df = pd.read_csv(args.csv, sep=",|\t", engine="python")

    # Validate presence of expected collector columns (allow extra columns)
    missing = [c for c in COLLECTOR_COLUMNS if c not in df.columns]
    if missing:
        logging.error("CSV missing required collector columns: %s", missing)
        return

    model = FlowModel()
    acc, auc = model.train(df)

    model.save(args.out_model, args.out_meta)

    logging.info("Training complete.")
    logging.info("Final ACC=%.4f | AUC=%.4f", acc, auc)


if __name__ == '__main__':
    main()
