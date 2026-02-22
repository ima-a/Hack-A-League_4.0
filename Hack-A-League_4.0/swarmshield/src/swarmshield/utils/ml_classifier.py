"""
CIC ML Classifier — light addon layer for SwarmShield Analyzer.

Wraps the CIC-IDS2017 XGBoost multi-class model saved at
``src/swarmshield/model/cic_multiclass_model.pkl``.

This module is **opt-in** — if the model or its dependencies are
unavailable the entire module degrades gracefully to no-ops.  The main
pipeline is never affected.

Usage
-----
    from swarmshield.utils.ml_classifier import get_classifier

    clf = get_classifier()
    if clf.available:
        label, confidence, is_attack = clf.predict(stats_dict)
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model location
# ---------------------------------------------------------------------------
_HERE       = Path(__file__).parent               # utils/
_MODEL_PATH = _HERE.parent / "model" / "cic_multiclass_model.pkl"

# ---------------------------------------------------------------------------
# Labels that should trigger a block action
# (everything except BENIGN is treated as hostile)
# ---------------------------------------------------------------------------
CIC_BLOCK_LABELS: frozenset[str] = frozenset({
    "Bot",
    "DDoS",
    "FTP-Patator",
    "Infiltration",
    "PortScan",
    "SSH-Patator",
    # Raw label from LabelEncoder (replacement char variant)
    "Web Attack \ufffd Brute Force",
    "Web Attack \ufffd Sql Injection",
    "Web Attack \ufffd XSS",
    # Normalised after \ufffd -> '-' substitution
    "Web Attack - Brute Force",
    "Web Attack - Sql Injection",
    "Web Attack - XSS",
})

# ---------------------------------------------------------------------------
# Feature mapping:  CIC column name  →  Scout stats key  (or constant 0)
#
# Scout stats keys available per _compute_stats():
#   packets_per_second, bytes_per_second, unique_dest_ips,
#   syn_count, port_entropy, window_seconds
#
# We convert window_seconds → microseconds for Flow Duration.
# Everything else defaults to 0 — the model degrades gracefully.
# ---------------------------------------------------------------------------
def _build_feature_vector(stats: dict, model_feature_names: list) -> list:
    """Map scout stats dict → ordered feature vector for the CIC model."""

    pps    = float(stats.get("packets_per_second", 0.0))
    bps    = float(stats.get("bytes_per_second",   0.0))
    syns   = float(stats.get("syn_count",          0))
    window = float(stats.get("window_seconds",     10))
    total_pkts = pps * window          # approximate total fwd packet count
    total_bytes = bps * window         # approximate total fwd bytes

    _SCOUT_MAP: dict[str, float] = {
        "Destination Port":           0.0,
        "Flow Duration":              window * 1_000_000,   # μs
        "Total Fwd Packets":          total_pkts,
        "Total Backward Packets":     0.0,
        "Total Length of Fwd Packets": total_bytes,
        "Total Length of Bwd Packets": 0.0,
        "Fwd Packet Length Max":      total_bytes / max(total_pkts, 1),
        "Fwd Packet Length Min":      0.0,
        "Fwd Packet Length Mean":     total_bytes / max(total_pkts, 1),
        "Fwd Packet Length Std":      0.0,
        "Bwd Packet Length Max":      0.0,
        "Bwd Packet Length Min":      0.0,
        "Bwd Packet Length Mean":     0.0,
        "Bwd Packet Length Std":      0.0,
        "Flow Bytes/s":               bps,
        "Flow Packets/s":             pps,
        "Flow IAT Mean":              (window * 1_000_000) / max(total_pkts, 1),
        "Flow IAT Std":               0.0,
        "Flow IAT Max":               window * 1_000_000,
        "Flow IAT Min":               0.0,
        "Fwd IAT Total":              window * 1_000_000,
        "Fwd IAT Mean":               (window * 1_000_000) / max(total_pkts, 1),
        "Fwd IAT Std":                0.0,
        "Fwd IAT Max":                window * 1_000_000,
        "Fwd IAT Min":                0.0,
        "Bwd IAT Total":              0.0,
        "Bwd IAT Mean":               0.0,
        "Bwd IAT Std":                0.0,
        "Bwd IAT Max":                0.0,
        "Bwd IAT Min":                0.0,
        "Fwd PSH Flags":              0.0,
        "Bwd PSH Flags":              0.0,
        "Fwd URG Flags":              0.0,
        "Bwd URG Flags":              0.0,
        "Fwd Header Length":          total_pkts * 20,  # assume 20-byte IP header
        "Bwd Header Length":          0.0,
        "Fwd Packets/s":              pps,
        "Bwd Packets/s":              0.0,
        "Min Packet Length":          0.0,
        "Max Packet Length":          total_bytes / max(total_pkts, 1),
        "Packet Length Mean":         total_bytes / max(total_pkts, 1),
        "Packet Length Std":          0.0,
        "Packet Length Variance":     0.0,
        "FIN Flag Count":             0.0,
        "SYN Flag Count":             syns,
        "RST Flag Count":             0.0,
        "PSH Flag Count":             0.0,
        "ACK Flag Count":             0.0,
        "URG Flag Count":             0.0,
        "CWE Flag Count":             0.0,
        "ECE Flag Count":             0.0,
        "Down/Up Ratio":              0.0,
        "Average Packet Size":        total_bytes / max(total_pkts, 1),
        "Avg Fwd Segment Size":       total_bytes / max(total_pkts, 1),
        "Avg Bwd Segment Size":       0.0,
        "Fwd Header Length.1":        total_pkts * 20,
        "Fwd Avg Bytes/Bulk":         0.0,
        "Fwd Avg Packets/Bulk":       0.0,
        "Fwd Avg Bulk Rate":          0.0,
        "Bwd Avg Bytes/Bulk":         0.0,
        "Bwd Avg Packets/Bulk":       0.0,
        "Bwd Avg Bulk Rate":          0.0,
        "Subflow Fwd Packets":        total_pkts,
        "Subflow Fwd Bytes":          total_bytes,
        "Subflow Bwd Packets":        0.0,
        "Subflow Bwd Bytes":          0.0,
        "Init_Win_bytes_forward":     0.0,
        "Init_Win_bytes_backward":    0.0,
        "act_data_pkt_fwd":           total_pkts,
        "min_seg_size_forward":       0.0,
        "Active Mean":                0.0,
        "Active Std":                 0.0,
        "Active Max":                 0.0,
        "Active Min":                 0.0,
        "Idle Mean":                  window * 1_000_000,
        "Idle Std":                   0.0,
        "Idle Max":                   window * 1_000_000,
        "Idle Min":                   0.0,
    }

    return [_SCOUT_MAP.get(str(f), 0.0) for f in model_feature_names]


# ---------------------------------------------------------------------------
# Classifier wrapper
# ---------------------------------------------------------------------------

class CICClassifier:
    """
    Lazy-loading wrapper around the CIC-IDS2017 XGBoost model.

    Attributes
    ----------
    available : bool
        True once the model loaded successfully.
    """

    def __init__(self, model_path: Path = _MODEL_PATH) -> None:
        self._path    = model_path
        self._lock    = threading.Lock()
        self._loaded  = False
        self._model   = None
        self._encoder = None
        self._feature_names: list = []
        self.available = False

    # ------------------------------------------------------------------
    def _load(self) -> None:
        """Load model on first use (thread-safe)."""
        with self._lock:
            if self._loaded:
                return
            try:
                import joblib  # noqa: PLC0415
                if not self._path.exists():
                    logger.warning(
                        "[CIC-ML] model file not found: %s — ML layer disabled",
                        self._path,
                    )
                    self._loaded = True
                    return
                obj = joblib.load(self._path)
                # Stored as (XGBClassifier, LabelEncoder)
                if isinstance(obj, (tuple, list)) and len(obj) == 2:
                    self._model, self._encoder = obj
                elif isinstance(obj, dict):
                    self._model   = obj.get("model")
                    self._encoder = obj.get("encoder") or obj.get("label_encoder")
                else:
                    self._model = obj
                if self._model is not None and hasattr(self._model, "feature_names_in_"):
                    self._feature_names = list(self._model.feature_names_in_)
                self.available = self._model is not None
                if self.available:
                    n_classes = (
                        len(self._encoder.classes_)
                        if self._encoder is not None else "unknown"
                    )
                    logger.info(
                        "[CIC-ML] loaded XGBoost model — %d features, %s classes",
                        len(self._feature_names), n_classes,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("[CIC-ML] could not load model (%s) — ML layer disabled", exc)
            finally:
                self._loaded = True

    # ------------------------------------------------------------------
    def ensure_loaded(self) -> "CICClassifier":
        """Trigger lazy model load if not yet done. Returns self for chaining."""
        if not self._loaded:
            self._load()
        return self

    # ------------------------------------------------------------------
    def predict(self, stats: dict) -> Tuple[Optional[str], float, bool]:
        """
        Classify a Scout stats dict.

        Parameters
        ----------
        stats : dict
            Output of ``_compute_stats()`` — keys: packets_per_second,
            bytes_per_second, syn_count, unique_dest_ips, port_entropy,
            window_seconds.

        Returns
        -------
        (label, confidence, is_attack)
            label      — class name string, e.g. "DDoS" or "BENIGN", or None
            confidence — probability of the predicted class [0, 1]
            is_attack  — True if label is in CIC_BLOCK_LABELS
        """
        if not self._loaded:
            self._load()
        if not self.available:
            return None, 0.0, False

        try:
            import numpy as np  # noqa: PLC0415

            vec  = _build_feature_vector(stats, self._feature_names)
            arr  = np.array([vec], dtype=float)
            proba = self._model.predict_proba(arr)[0]   # shape: (n_classes,)
            idx  = int(proba.argmax())
            conf = float(proba[idx])

            if self._encoder is not None:
                label = str(self._encoder.inverse_transform([idx])[0])
            else:
                label = str(idx)

            # Normalise labels: replace Unicode replacement char with dash
            label_clean = label.replace("\ufffd", "-")
            is_attack   = label_clean in CIC_BLOCK_LABELS or label in CIC_BLOCK_LABELS
            return label_clean, conf, is_attack

        except Exception as exc:  # noqa: BLE001
            logger.debug("[CIC-ML] predict error: %s", exc)
            return None, 0.0, False


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_instance: Optional[CICClassifier] = None
_inst_lock = threading.Lock()


def get_classifier() -> CICClassifier:
    """Return the module-level CICClassifier singleton (lazy-initialised)."""
    global _instance
    if _instance is None:
        with _inst_lock:
            if _instance is None:
                _instance = CICClassifier()
    return _instance
