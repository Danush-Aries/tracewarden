"""Reporters (SARIF / HTML / terminal) and CLI smoke tests."""

import json
import os

from tracewarden import cli, engine
from tracewarden.reporters import build_sarif, render_html, render_terminal, write_html, write_sarif
from conftest import EXAMPLES_DIR

FLAGSHIP = os.path.join(EXAMPLES_DIR, "malicious_github_issue_exfil_openai.json")


def test_sarif_is_valid_and_maps_rules():
    results = engine.scan_path(EXAMPLES_DIR)
    doc = build_sarif(results)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "tracewarden"
    # every result's ruleId must be present in the declared rule descriptors
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in declared
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert len(run["results"]) > 0


def test_sarif_write_roundtrips(tmp_path):
    results = engine.scan_path(EXAMPLES_DIR)
    out = tmp_path / "out.sarif"
    write_sarif(results, str(out))
    doc = json.loads(out.read_text())
    assert doc["runs"][0]["results"]


def test_html_report_contains_findings(tmp_path):
    results = engine.scan_path(EXAMPLES_DIR)
    html = render_html(results)
    assert "<!DOCTYPE html>" in html
    assert "trace" in html.lower()
    assert "TW023" in html  # lethal trifecta finding rendered
    out = tmp_path / "report.html"
    write_html(results, str(out))
    assert out.exists() and out.stat().st_size > 0


def test_terminal_report_plain_mode():
    results = engine.scan_path(EXAMPLES_DIR)
    text = render_terminal(results, use_color=False)
    assert "tracewarden" in text
    assert "Summary" in text


def test_cli_scan_exit_zero_without_failon(capsys):
    rc = cli.main(["scan", EXAMPLES_DIR, "--no-color"])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    assert "tracewarden" in out


def test_cli_scan_failon_critical_returns_nonzero():
    rc = cli.main(["scan", FLAGSHIP, "--fail-on", "critical", "--no-color"])
    assert rc == cli.EXIT_FINDINGS


def test_cli_scan_failon_not_triggered_on_clean_trace():
    clean = os.path.join(EXAMPLES_DIR, "benign_weather_openai.json")
    rc = cli.main(["scan", clean, "--fail-on", "LOW", "--no-color"])
    assert rc == cli.EXIT_OK


def test_cli_scan_writes_artifacts(tmp_path):
    html = tmp_path / "r.html"
    sarif = tmp_path / "r.sarif"
    js = tmp_path / "r.json"
    rc = cli.main([
        "scan", FLAGSHIP, "--no-color",
        "--html", str(html), "--sarif", str(sarif), "--json", str(js),
    ])
    assert rc == cli.EXIT_OK
    assert html.exists() and sarif.exists() and js.exists()
    payload = json.loads(js.read_text())
    assert payload["tool"] == "tracewarden"
    assert payload["summary"]["total"] > 0


def test_cli_rules_lists_all_28(capsys):
    rc = cli.main(["rules"])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    assert "TW001" in out and "TW028" in out


def test_cli_rules_json(capsys):
    rc = cli.main(["rules", "--json"])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    data = json.loads(out)
    assert len(data) == 28
    assert all({"id", "severity", "owasp"} <= set(r) for r in data)


def test_cli_scan_missing_path_errors():
    rc = cli.main(["scan", "/no/such/path/here.json", "--no-color"])
    assert rc == cli.EXIT_ERROR
