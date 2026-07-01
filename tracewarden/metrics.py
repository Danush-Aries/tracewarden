"""Precision / recall evaluation of the rule engine against labelled traces.

Ground truth lives in ``examples/labels.json`` mapping each example file to the
set of rule ids that *should* fire. We compare against the engine's actual
output to compute aggregate precision, recall and F1 - the same numbers quoted
in the README so the claim is reproducible with ``pytest``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Set

from . import engine


@dataclass
class EvalResult:
    tp: int
    fp: int
    fn: int
    per_file: Dict[str, Dict[str, list]]

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
        }


def load_labels(examples_dir: str) -> Dict[str, List[str]]:
    with open(os.path.join(examples_dir, "labels.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def predicted_rule_ids(path: str) -> Set[str]:
    return {f.rule_id for f in engine.scan_file(path)}


def evaluate(examples_dir: str) -> EvalResult:
    labels = load_labels(examples_dir)
    tp = fp = fn = 0
    per_file: Dict[str, Dict[str, list]] = {}

    for filename, expected_list in labels.items():
        path = os.path.join(examples_dir, filename)
        expected = set(expected_list)
        predicted = predicted_rule_ids(path)

        file_tp = sorted(expected & predicted)
        file_fp = sorted(predicted - expected)
        file_fn = sorted(expected - predicted)

        tp += len(file_tp)
        fp += len(file_fp)
        fn += len(file_fn)
        per_file[filename] = {"tp": file_tp, "fp": file_fp, "fn": file_fn}

    return EvalResult(tp=tp, fp=fp, fn=fn, per_file=per_file)


def classification_metrics(examples_dir: str) -> dict:
    """Trace-level malicious/benign classification accuracy.

    A trace is predicted 'malicious' if it has any HIGH+ finding. Ground truth
    is derived from the filename convention (malicious_* vs benign_*).
    """
    from .schema import severity_rank

    labels = load_labels(examples_dir)
    tp = fp = tn = fn = 0
    for filename in labels:
        path = os.path.join(examples_dir, filename)
        findings = engine.scan_file(path)
        flagged = any(severity_rank(f.severity) >= severity_rank("HIGH") for f in findings)
        is_malicious = filename.startswith("malicious")
        if is_malicious and flagged:
            tp += 1
        elif is_malicious and not flagged:
            fn += 1
        elif not is_malicious and flagged:
            fp += 1
        else:
            tn += 1
    total = tp + fp + tn + fn
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": round((tp + tn) / total, 3) if total else 1.0,
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else 1.0,
        "recall": round(tp / (tp + fn), 3) if (tp + fn) else 1.0,
    }
