"""Assert each shipped example fires exactly its labeled rule set + P/R metrics."""

import json
import os

import pytest

from tracewarden import engine, metrics
from tracewarden.schema import severity_rank
from conftest import EXAMPLES_DIR


def _labels():
    with open(os.path.join(EXAMPLES_DIR, "labels.json"), encoding="utf-8") as fh:
        return json.load(fh)


LABELS = _labels()


@pytest.mark.parametrize("filename", sorted(LABELS))
def test_example_fires_expected_rules(filename):
    expected = set(LABELS[filename])
    predicted = {f.rule_id for f in engine.scan_file(os.path.join(EXAMPLES_DIR, filename))}
    assert expected <= predicted, (
        f"{filename}: missing expected rules {expected - predicted}"
    )


@pytest.mark.parametrize("filename", sorted(f for f in LABELS if f.startswith("benign")))
def test_benign_examples_stay_clean(filename):
    findings = engine.scan_file(os.path.join(EXAMPLES_DIR, filename))
    assert findings == [], f"{filename} should be clean but produced {findings}"


@pytest.mark.parametrize("filename", sorted(f for f in LABELS if f.startswith("malicious")))
def test_malicious_examples_flag_high_severity(filename):
    findings = engine.scan_file(os.path.join(EXAMPLES_DIR, filename))
    assert any(severity_rank(f.severity) >= severity_rank("HIGH") for f in findings)


def test_flagship_github_issue_detects_trifecta_and_injection():
    path = os.path.join(EXAMPLES_DIR, "malicious_github_issue_exfil_openai.json")
    ids = {f.rule_id for f in engine.scan_file(path)}
    # indirect prompt injection -> secret access -> external exfiltration
    assert "TW022" in ids  # injected instructions in the fetched issue
    assert "TW023" in ids  # lethal trifecta
    assert "TW020" in ids  # untrusted content flows into network egress


def test_precision_recall_on_examples():
    res = metrics.evaluate(EXAMPLES_DIR)
    assert res.tp > 0
    assert res.recall == 1.0        # every labeled rule is caught
    assert res.precision >= 0.9     # few/no over-fires on the labeled corpus


def test_trace_level_classification_accuracy():
    m = metrics.classification_metrics(EXAMPLES_DIR)
    assert m["accuracy"] >= 0.9
    assert m["recall"] == 1.0
