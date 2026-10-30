"""Run one pipeline stage (ingest | detect) in this process and report wall time and
peak memory. Stages are run as separate processes by the validation script so each
peak belongs to exactly one stage.

    python -m agentsoc.evaluation.measure ingest <ingest CLI args>
    python -m agentsoc.evaluation.measure detect <detect CLI args>

The last stdout line is `AGENTSOC_METRICS {json}`.
"""

from __future__ import annotations

import ctypes
import json
import sys
import time
from ctypes import wintypes

METRICS_PREFIX = "AGENTSOC_METRICS "


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def peak_memory_bytes() -> int | None:
    """Peak resident memory of this process (Windows: peak working set; POSIX: max RSS)."""
    if sys.platform == "win32":
        # Explicit signatures: without them ctypes passes the pseudo-handle as a 32-bit int
        # on 64-bit Python and the call fails.
        get_process = ctypes.windll.kernel32.GetCurrentProcess
        get_process.restype = wintypes.HANDLE
        get_info = ctypes.windll.psapi.GetProcessMemoryInfo
        get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessMemoryCounters),
                             wintypes.DWORD]
        get_info.restype = wintypes.BOOL
        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        ok = get_info(get_process(), ctypes.byref(counters), counters.cb)
        return int(counters.PeakWorkingSetSize) if ok else None
    import resource

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss if sys.platform == "darwin" else rss * 1024  # Linux reports KiB


def main(argv: list[str] | None = None) -> int:
    from agentsoc.cli import detect_main, ingest_main

    args = list(sys.argv[1:] if argv is None else argv)
    stages = {"ingest": ingest_main, "detect": detect_main}
    if not args or args[0] not in stages:
        print(f"usage: measure {{{'|'.join(stages)}}} <stage args>")
        return 2
    start = time.perf_counter()
    exit_code = stages[args[0]](args[1:])
    metrics = {
        "stage": args[0],
        "exit_code": exit_code,
        "wall_seconds": round(time.perf_counter() - start, 3),
        "peak_memory_bytes": peak_memory_bytes(),
    }
    print(METRICS_PREFIX + json.dumps(metrics), flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
