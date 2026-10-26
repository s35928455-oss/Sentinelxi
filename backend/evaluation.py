"""
SentinelX AI - Detection Engine Evaluation Module
Evaluates rule-based detection performance against labelled security log datasets.
Computes real Precision, Recall, F1 scores, per-class metrics, and confusion matrix.
"""

import csv
import io
import os
from typing import Any, Dict, List, Optional, Set
from log_parser import normalize_record

EVAL_LIMITATIONS = (
    "This evaluation uses a synthetic benchmark dataset with known ground-truth attack "
    "patterns (brute force, port scan, login burst) and benign background traffic. "
    "In live production environments, metrics may vary based on network topology, log fidelity, "
    "distributed attack architectures, and custom authentication gateways. "
    "Continuous threshold calibration against enterprise baselines is recommended."
)


def load_labelled_data(path: str) -> List[Dict[str, Any]]:
    """
    Loads labelled test logs from CSV or JSON.
    Normalizes records and preserves the ground-truth 'label' field.
    
    Args:
        path: Path to the labelled data file.
        
    Returns:
        List of normalized event dicts containing 'label' attribute.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Labelled test dataset not found at path: {path}")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    events: List[Dict[str, Any]] = []

    if path.lower().endswith(".json"):
        import json
        data = json.loads(content)
        records = data if isinstance(data, list) else data.get("events", [data])
        for idx, row in enumerate(records, start=1):
            if not isinstance(row, dict):
                continue
            label = str(row.get("label") or row.get("ground_truth") or row.get("class") or "normal").strip().lower()
            norm = normalize_record(row, index=idx)
            norm["label"] = label
            events.append(norm)
    else:
        # CSV parsing
        reader = csv.DictReader(io.StringIO(content))
        for idx, row in enumerate(reader, start=1):
            if not row or not any(str(v).strip() for v in row.values() if v is not None):
                continue
            # Extract label before normalization
            label = "normal"
            for label_key in ("label", "ground_truth", "class", "target", "attack_type"):
                for k in row:
                    if k.strip().lower() == label_key:
                        label = str(row[k]).strip().lower()
                        break
                if label != "normal":
                    break

            try:
                norm = normalize_record(row, index=idx)
                norm["label"] = label
                events.append(norm)
            except Exception:
                continue

    return events


def evaluate_detector(detector: Any, labelled_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Runs the detection engine on labelled events and computes empirical evaluation metrics.
    
    Maps detected incident evidence_event_ids back to ground-truth event labels to calculate:
    - True Positives (TP), False Positives (FP), False Negatives (FN), True Negatives (TN)
    - Precision, Recall, and F1 Score (per-class and micro/macro overall)
    - Full confusion matrix
    
    Args:
        detector: An instance of DetectionEngine
        labelled_events: List of normalized events with 'label' attributes
        
    Returns:
        Dictionary containing overall and per-class performance metrics.
    """
    if not labelled_events:
        return {
            "overall": {"precision": 0.0, "recall": 0.0, "f1": 0.0, "macro_f1": 0.0},
            "per_class": {},
            "confusion_matrix": {},
            "total_events": 0,
            "total_labelled": 0,
            "total_incidents": 0,
            "limitations": EVAL_LIMITATIONS
        }

    # Run detection engine on events
    incidents = detector.run_all_rules(labelled_events)

    # Build mapping from event_id to set of predicted incident types
    # Each incident's evidence_event_ids represents the detector predicting that incident_type
    predicted_types_by_eid: Dict[str, Set[str]] = {}
    for inc in incidents:
        itype = inc.incident_type
        for eid in inc.evidence_event_ids:
            predicted_types_by_eid.setdefault(eid, set()).add(itype)

    # Identify all attack classes present in either labels or detector outputs
    all_known_classes = {"brute_force", "port_scan", "login_burst"}
    for ev in labelled_events:
        lbl = ev.get("label", "normal")
        if lbl and lbl != "normal":
            all_known_classes.add(lbl)

    attack_classes = sorted(list(all_known_classes))
    all_classes_with_normal = ["normal"] + attack_classes

    # Confusion matrix: actual -> predicted -> count
    confusion_matrix: Dict[str, Dict[str, int]] = {
        act: {pred: 0 for pred in all_classes_with_normal}
        for act in all_classes_with_normal
    }

    per_class_metrics: Dict[str, Dict[str, Any]] = {}
    total_events = len(labelled_events)

    # Populate confusion matrix and event predictions
    for ev in labelled_events:
        eid = str(ev.get("event_id", ""))
        actual = str(ev.get("label", "normal")).strip().lower()
        if actual not in confusion_matrix:
            confusion_matrix[actual] = {pred: 0 for pred in all_classes_with_normal}

        preds = predicted_types_by_eid.get(eid, set())
        if not preds:
            # Predicted benign/normal
            confusion_matrix[actual]["normal"] += 1
        else:
            # If multiple predictions, credit each or the first
            for p in preds:
                if p in confusion_matrix[actual]:
                    confusion_matrix[actual][p] += 1
                else:
                    confusion_matrix[actual].setdefault(p, 0)
                    confusion_matrix[actual][p] += 1

    # Calculate per-class metrics for each attack category
    micro_tp = 0
    micro_fp = 0
    micro_fn = 0
    f1_sum = 0.0

    for cls in attack_classes:
        tp = 0
        fp = 0
        fn = 0
        tn = 0

        for ev in labelled_events:
            eid = str(ev.get("event_id", ""))
            actual_is_cls = (str(ev.get("label", "normal")).strip().lower() == cls)
            pred_is_cls = (cls in predicted_types_by_eid.get(eid, set()))

            if actual_is_cls and pred_is_cls:
                tp += 1
            elif not actual_is_cls and pred_is_cls:
                fp += 1
            elif actual_is_cls and not pred_is_cls:
                fn += 1
            else:
                tn += 1

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = ((tp + tn) / total_events) if total_events > 0 else 0.0

        per_class_metrics[cls] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "support": tp + fn,
        }

        micro_tp += tp
        micro_fp += fp
        micro_fn += fn
        f1_sum += f1

    # Overall metrics across all attack detection classes
    overall_prec = (micro_tp / (micro_tp + micro_fp)) if (micro_tp + micro_fp) > 0 else 0.0
    overall_rec = (micro_tp / (micro_tp + micro_fn)) if (micro_tp + micro_fn) > 0 else 0.0
    overall_f1 = (2 * overall_prec * overall_rec / (overall_prec + overall_rec)) if (overall_prec + overall_rec) > 0 else 0.0
    macro_f1 = (f1_sum / len(attack_classes)) if attack_classes else 0.0

    return {
        "overall": {
            "precision": round(overall_prec, 4),
            "recall": round(overall_rec, 4),
            "f1": round(overall_f1, 4),
            "macro_f1": round(macro_f1, 4),
            "total_incidents_detected": len(incidents),
        },
        "per_class": per_class_metrics,
        "confusion_matrix": confusion_matrix,
        "total_events": total_events,
        "total_labelled": len([e for e in labelled_events if e.get("label") != "normal"]),
        "limitations": EVAL_LIMITATIONS,
    }
