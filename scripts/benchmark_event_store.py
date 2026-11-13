"""Measure the SQLite event index on real datasets and write a report.

    python scripts/benchmark_event_store.py --out docs/phaseA_event_store_benchmark.md

Each step runs in its own process so its peak memory is measured on its own. Datasets are
only read; indexes are written to a temporary directory and deleted. Single runs on one
machine: indicative, not a performance guarantee.
"""

import argparse
import ctypes
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from agentsoc.config import PROJECT_ROOT

DATASETS = [
    ("Synthetic demo", "data/processed/demo/dataset"),
    ("LANL window, 100k (real)", "data/processed/lanl_validation/datasets/lines_1_100000"),
    ("LANL red-team window, 400k (real)",
     "data/processed/lanl_validation/datasets/lines_29400001_29800000"),
    ("LANL window, 500k (real)", "data/processed/lanl_validation/datasets/lines_1_500000"),
]


def peak_mb() -> float:
    if os.name == "nt":
        class Counters(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        kernel32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters),
                                               ctypes.c_ulong]
        if not psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(),
                                          ctypes.byref(counters), counters.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return counters.PeakWorkingSetSize / 2**20
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def child(step: str, dataset: str, index: str) -> dict:
    from agentsoc.store import eventdb
    from agentsoc.store.datasets import load_events, load_manifest
    start = time.perf_counter()
    result: dict = {}
    if step == "load_events":
        result["events"] = len(load_events(dataset))
    elif step == "build":
        result["events"] = eventdb.build_index(dataset, index, source_key="bench").event_count
        result["index_mb"] = Path(index).stat().st_size / 2**20
    elif step == "export":
        out = Path(index).with_suffix(".jsonl")
        result["identical"] = eventdb.export_jsonl(index, out) == load_manifest(
            dataset).events_sha256
        out.unlink()
    elif step == "queries":
        events, total = eventdb.search(index, eventdb.EventQuery(), page_size=1)
        first = events[0]
        last = eventdb.search(index, eventdb.EventQuery(), page=total, page_size=1)[0][0]
        span = last.timestamp - first.timestamp
        window_start = first.timestamp + span * 3 / 8  # the middle quarter of the data
        window_end = first.timestamp + span * 5 / 8
        bucket = max(60, int(span.total_seconds() / 48))
        result["span_hours"] = span.total_seconds() / 3600
        result["bucket_seconds"] = bucket
        cases = {
            "first page, no filter": eventdb.EventQuery(),
            "user substring": eventdb.EventQuery(user=first.src_user[:4]),
            "host substring": eventdb.EventQuery(host=first.src_host[1:4]),
            "failures in the middle quarter of the time span": eventdb.EventQuery(
                outcome="Fail", start=window_start, end=window_end),
            "rare value (few matches)": eventdb.EventQuery(user="zz-no-such-user"),
        }
        for name, query in cases.items():
            runs = []
            for _ in range(5):
                t = time.perf_counter()
                _, total = eventdb.search(index, query, page_size=50)
                runs.append((time.perf_counter() - t) * 1000)
            result[name] = {"ms": statistics.median(runs), "matches": total}
        runs = []
        for _ in range(5):
            t = time.perf_counter()
            eventdb.search(index, eventdb.EventQuery(), page=1000, page_size=50)
            runs.append((time.perf_counter() - t) * 1000)
        result["page 1,000 (offset 49,950)"] = {"ms": statistics.median(runs), "matches": None}
        runs = []
        for _ in range(5):
            t = time.perf_counter()
            buckets = eventdb.outcome_histogram(index, bucket)
            runs.append((time.perf_counter() - t) * 1000)
        result["success/failure histogram (about 48 buckets)"] = {"ms": statistics.median(runs),
                                                      "matches": len(buckets)}
    result["seconds"] = time.perf_counter() - start
    result["peak_mb"] = peak_mb()
    return result


def run(step: str, dataset: Path, index: Path) -> dict:
    out = subprocess.run(  # noqa: S603 — this script, fixed arguments
        [sys.executable, __file__, "--child", step, str(dataset), str(index)],
        capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="docs/phaseA_event_store_benchmark.md")
    parser.add_argument("--child", nargs=3)
    args = parser.parse_args()
    if args.child:
        print(json.dumps(child(*args.child)))
        return 0
    rows, queries = [], {}
    with tempfile.TemporaryDirectory() as work:
        for label, rel in DATASETS:
            dataset = PROJECT_ROOT / rel
            if not dataset.is_dir():
                rows.append((label, None))
                continue
            index = Path(work) / f"{dataset.name}.sqlite"
            print(f"{label} ...", flush=True)
            measured = {step: run(step, dataset, index)
                        for step in ("load_events", "build", "export", "queries")}
            rows.append((label, measured))
            queries[label] = measured["queries"]
            index.unlink()
    lines = [
        "# Phase A — SQLite event index benchmark", "",
        f"_Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC by `scripts/benchmark_event_store.py` "
        f"on {platform.system()} {platform.release()}, Python {platform.python_version()}. "
        "Single runs on one machine; indicative only._", "",
        "Each step ran in its own process; memory is that process's peak working set. "
        "\"Full load\" is what the detection, graph and risk engines do today "
        "(`load_events`): it is shown for comparison, and the index does not change it.", "",
        "| Dataset | Events | Full load: s / peak MB | Index build: s / peak MB | Index size MB "
        "| Export s | Export byte-identical |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for label, m in rows:
        if m is None:
            lines.append(f"| {label} | not available on this machine | | | | | |")
            continue
        load, build, export = m["load_events"], m["build"], m["export"]
        lines.append(
            f"| {label} | {build['events']:,} | {load['seconds']:.1f} / {load['peak_mb']:.0f} "
            f"| {build['seconds']:.1f} / {build['peak_mb']:.0f} | {build['index_mb']:.0f} "
            f"| {export['seconds']:.1f} | {'yes' if export['identical'] else '**NO**'} |")
    lines += ["", "## Query latency (median of 5, page size 50, includes the total count)", ""]
    names = list(next(iter(queries.values())).keys() - {
        "seconds", "peak_mb", "span_hours", "bucket_seconds"}) if queries else []
    names.sort()
    lines.append("| Query | " + " | ".join(queries) + " |")
    lines.append("|---|" + "---:|" * len(queries))
    for name in names:
        cells = []
        for label in queries:
            q = queries[label][name]
            cells.append(f"{q['ms']:.1f} ms" + (f" ({q['matches']:,})" if q["matches"] is not None
                                                else ""))
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    lines += ["", "Time span covered: " + "; ".join(
        f"{label} {q['span_hours']:.1f} h" for label, q in queries.items()) + "."]
    lines += [
        "", "## Reading these numbers", "",
        "- Substring searches (`LIKE '%x%'`) cannot use an index, so they scan the table; their "
        "cost grows with the dataset. Counting the total also scans every match.",
        "- Deep pages use `OFFSET`, which also grows with depth. Keyset pagination is the "
        "planned fix if deep paging matters in practice.",
        "- The index makes searching and counting cheap without loading events into memory. "
        "It does not reduce the memory the analysis engines need; that requires bounded "
        "analysis windows (Phase C/F).",
    ]
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
