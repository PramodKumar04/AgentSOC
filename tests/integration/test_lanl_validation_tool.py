"""End-to-end run of the validation orchestrator on a tiny SYNTHETIC LANL-format archive.

Exercises the real subprocess stages (ingest, detect) and all five output files. Says
nothing about LANL detection quality — it only proves the tooling is wired correctly.
"""

import gzip
import json

from agentsoc.evaluation.validate import main

LINES = [f"{t},U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Fail" for t in range(1, 6)]
LINES += [
    "6,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
    "10,U2@DOM1,U2@DOM1,C3,C4,Kerberos,Network,LogOn,Success",
    "200,U2@DOM1,U2@DOM1,C3,C5,Kerberos,Network,LogOn,Success",
    "210,U2@DOM1,U2@DOM1,C5,C6,Kerberos,Network,LogOn,Success",
]


def test_orchestrator_produces_all_outputs(tmp_path, capsys):
    archive = tmp_path / "auth.txt.gz"
    with gzip.open(archive, "wt") as handle:
        handle.write("\n".join(LINES) + "\n")
    redteam = tmp_path / "redteam.txt"
    redteam.write_text("210,U2@DOM1,C5,C6\n")
    out = tmp_path / "validation"

    code = main([
        "--archive", str(archive), "--redteam", str(redteam), "--out", str(out),
        "--scan-days", "1",
        "--run", "all:0:100", "--run", "all_short:0:100:half_window",
    ])
    assert code == 0, capsys.readouterr().out

    for name in ("ingestion_summary.json", "detection_summary.json", "rule_analysis.json",
                 "performance_metrics.json", "validation_report.md"):
        assert (out / name).is_file()

    ingestion = json.loads((out / "ingestion_summary.json").read_text())
    assert ingestion["runs"]["all"]["provenance"] == "lanl"
    assert ingestion["archive"]["lines_per_day"] == {"day_0": len(LINES)}

    detection = json.loads((out / "detection_summary.json").read_text())
    default, short = detection["runs"]["all"], detection["runs"]["all_short"]
    assert default["integrity"]["passed"] and short["integrity"]["passed"]
    assert default["findings_by_rule"]["NEW_DST_HOST"] == 0  # 2-day baseline not covered
    assert short["spec"]["baseline_seconds"] == (210 - 1) // 2
    assert short["findings_by_rule"]["LATERAL_CHAIN"] == 1  # C3 > C5 > C6 after short baseline
    assert short["redteam"]["labels_matched_to_events"] == 1
    assert short["redteam"]["matched_cited_by_any_finding"] == 1

    perf = json.loads((out / "performance_metrics.json").read_text())
    assert perf["runs"]["all"]["ingest"]["peak_memory_bytes"] > 0
    assert perf["runs"]["all"]["detect"]["exit_code"] == 0

    report = (out / "validation_report.md").read_text(encoding="utf-8")
    assert "not proof of production detection accuracy" in report
    assert "## 11. Recommendations" in report
    for run in detection["runs"].values():
        assert not {"precision", "recall", "f1", "accuracy"} & set(run["redteam"])
