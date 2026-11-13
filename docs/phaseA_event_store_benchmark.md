# Phase A — SQLite event index benchmark

_Generated 2026-11-13 13:14 UTC by `scripts/benchmark_event_store.py` on Windows 10, Python 3.11.5. Single runs on one machine; indicative only._

Each step ran in its own process; memory is that process's peak working set. "Full load" is what the detection, graph and risk engines do today (`load_events`): it is shown for comparison, and the index does not change it.

| Dataset | Events | Full load: s / peak MB | Index build: s / peak MB | Index size MB | Export s | Export byte-identical |
|---|---:|---:|---:|---:|---:|---|
| Synthetic demo | 176 | 0.0 / 38 | 0.0 / 38 | 0 | 0.0 | yes |
| LANL window, 100k (real) | 100,000 | 2.0 / 231 | 2.8 / 45 | 23 | 2.8 | yes |
| LANL red-team window, 400k (real) | 400,000 | 8.5 / 819 | 11.7 / 46 | 101 | 11.2 | yes |
| LANL window, 500k (real) | 500,000 | 10.1 / 1003 | 14.5 / 46 | 120 | 14.2 | yes |

## Query latency (median of 5, page size 50, includes the total count)

| Query | Synthetic demo | LANL window, 100k (real) | LANL red-team window, 400k (real) | LANL window, 500k (real) |
|---|---:|---:|---:|---:|
| failures in the middle quarter of the time span | 1.5 ms (0) | 2.6 ms (209) | 2.9 ms (443) | 3.3 ms (828) |
| first page, no filter | 2.3 ms (176) | 5.5 ms (100,000) | 11.3 ms (400,000) | 12.8 ms (500,000) |
| host substring | 2.4 ms (56) | 57.2 ms (132) | 204.4 ms (335) | 215.3 ms (510) |
| page 1,000 (offset 49,950) | 1.4 ms | 14.0 ms | 20.8 ms | 21.4 ms |
| rare value (few matches) | 1.6 ms (0) | 71.1 ms (0) | 298.5 ms (0) | 348.0 ms (0) |
| success/failure histogram (about 48 buckets) | 1.4 ms (21) | 67.8 ms (17) | 279.7 ms (36) | 335.8 ms (49) |
| user substring | 1.7 ms (8) | 39.4 ms (3,205) | 220.7 ms (181) | 174.7 ms (16,591) |

Time span covered: Synthetic demo 80.1 h; LANL window, 100k (real) 0.3 h; LANL red-team window, 400k (real) 0.6 h; LANL window, 500k (real) 1.4 h.

## Reading these numbers

- Substring searches (`LIKE '%x%'`) cannot use an index, so they scan the table; their cost grows with the dataset. Counting the total also scans every match.
- Deep pages use `OFFSET`, which also grows with depth. Keyset pagination is the planned fix if deep paging matters in practice.
- The index makes searching and counting cheap without loading events into memory. It does not reduce the memory the analysis engines need; that requires bounded analysis windows (Phase C/F).
