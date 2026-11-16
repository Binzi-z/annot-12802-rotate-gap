import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "auth.log")
LABELS = os.path.join(ROOT, "labels.json")

BENIGN_IPS = {"10.20.1.77", "10.20.1.88"}  # failed-then-success, rejected probes


def run(tmp_path, logs=None):
    out = tmp_path / "out.json"
    logs = logs or [LOG]
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "detector", "detector.py"),
         *logs, str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def finding_ips(result):
    return {f["entities"]["ip"] for f in result["findings"]}


def test_corpus_and_labels():
    assert os.path.exists(LOG)
    with open(LABELS, encoding="utf-8") as fh:
        assert len(json.load(fh)["events"]) == 2


def test_all_labels_detected(tmp_path):
    with open(LABELS, encoding="utf-8") as fh:
        labels = json.load(fh)["events"]
    result = run(tmp_path)
    got = {(f["rule"], f["entities"]["ip"]) for f in result["findings"]}
    for ev in labels:
        assert (ev["kind"], ev["ip"]) in got, f"missing {ev['kind']} for {ev['ip']}"


def test_zero_false_positives_on_benign_traffic(tmp_path):
    result = run(tmp_path)
    assert not (finding_ips(result) & BENIGN_IPS)
    # nothing beyond the two labelled events may alert
    assert len(result["findings"]) == 2


def test_findings_have_required_fields(tmp_path):
    result = run(tmp_path)
    for f in result["findings"]:
        for key in ("rule", "first_seen", "last_seen", "entities", "evidence"):
            assert f.get(key), f"{f.get('rule')} missing {key}"
        assert f["first_seen"] <= f["last_seen"]
        for ev in f["evidence"]:
            assert ev["file"] and ev["line"] > 0 and ev["timestamp"]


def test_evidence_is_a_cross_file_sequence(tmp_path):
    # split the attack across a simulated rotation boundary
    with open(LOG, encoding="utf-8") as fh:
        lines = fh.readlines()
    cut = 853  # upload lands in part1, the execution request in part2
    part1, part2 = tmp_path / "auth.log.1", tmp_path / "auth.log"
    part1.write_text("".join(lines[:cut]), encoding="utf-8")
    part2.write_text("".join(lines[cut:]), encoding="utf-8")

    result = run(tmp_path, logs=[str(part1), str(part2)])
    assert len(result["findings"]) == 2
    webshell = next(f for f in result["findings"] if f["rule"] == "webshell")
    # the upload->exec chain straddles the rotation boundary
    assert {ev["file"] for ev in webshell["evidence"]} == {str(part1), str(part2)}
    for f in result["findings"]:
        # original line numbers are preserved per file
        for ev in f["evidence"]:
            src = part1 if ev["file"] == str(part1) else part2
            assert ev["event"] == src.read_text(
                encoding="utf-8").splitlines()[ev["line"] - 1].rstrip("\n")


def test_needs_review_explains_gap(tmp_path):
    result = run(tmp_path)
    for item in result["needs_review"]:
        assert item.get("missing"), "needs_review must say what is missing"
        assert item.get("evidence")
    # the rejected 403 probes are uncertain, not an alert
    assert any(r["entities"]["ip"] == "10.20.1.88"
               for r in result["needs_review"])


def test_empty_log_yields_no_findings(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    result = run(tmp_path, logs=[str(empty)])
    assert result["findings"] == []
    assert result["needs_review"] == []
