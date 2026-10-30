"""File-level ingestion: streaming, windows, counters, ordering, file errors."""

import gzip
import hashlib
from datetime import datetime

import pytest

from agentsoc.exceptions import IngestionError
from agentsoc.perception.lanl import ingest_lanl_file
from agentsoc.perception.records import RejectReason
from agentsoc.schemas import DatasetSource

LINES = [
    "3,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
    "1,U2@DOM1,U2@DOM1,C3,C4,Kerberos,Network,LogOn,Fail",
    "",
    "1,U2@DOM1,U2@DOM1,C3,C4,Kerberos,Network,LogOn,Fail",
    "2,U3@DOM1,U3@DOM1,C5,C6,Kerberos,Network,LogIn,Success",
    "4,U4@DOM1,U4@DOM1,C7,C8,NTLM,Network,LogOn,Success",
]


def write(tmp_path, lines, name="auth.txt", gz=False):
    data = ("\n".join(lines) + "\n").encode("utf-8")
    path = tmp_path / name
    if gz:
        with gzip.open(path, "wb") as handle:
            handle.write(data)
    else:
        path.write_bytes(data)
    return path


def test_counts_and_sorting(tmp_path):
    result = ingest_lanl_file(write(tmp_path, LINES))
    assert result.lines_read == 6
    assert result.blank_lines == 1
    assert len(result.events) == 4
    assert [r.reason for r in result.rejected] == [RejectReason.INVALID_ORIENTATION]
    assert result.rejected[0].line == 5
    assert result.exact_duplicates == 1
    assert result.out_of_order == 2  # lines 2 and 4 precede line 1's time
    assert [e.raw_ref.line for e in result.events] == [2, 4, 1, 6]
    assert [e.timestamp for e in result.events] == sorted(e.timestamp for e in result.events)


def test_gzip_input_matches_plain(tmp_path):
    plain = ingest_lanl_file(write(tmp_path, LINES))
    gz = ingest_lanl_file(write(tmp_path, LINES, name="auth.txt.gz", gz=True))
    assert [e.model_dump(exclude={"raw_ref"}) for e in plain.events] == [
        e.model_dump(exclude={"raw_ref"}) for e in gz.events
    ]
    assert plain.input_sha256 == gz.input_sha256  # hash is over decompressed line bytes


def test_limit_and_skip_window_keeps_absolute_line_numbers(tmp_path):
    result = ingest_lanl_file(write(tmp_path, LINES), skip=3, limit=2)
    assert result.lines_read == 2
    assert sorted(e.raw_ref.line for e in result.events) == [4]
    assert result.rejected[0].line == 5
    assert (result.skip, result.limit) == (3, 2)


def test_input_hash_covers_consumed_lines_only(tmp_path):
    path = write(tmp_path, LINES)
    result = ingest_lanl_file(path, limit=2)
    expected = hashlib.sha256((LINES[0] + "\n" + LINES[1] + "\n").encode()).hexdigest()
    assert result.input_sha256 == expected


def test_crlf_file(tmp_path):
    path = tmp_path / "crlf.txt"
    path.write_bytes(("\r\n".join(LINES) + "\r\n").encode())
    assert len(ingest_lanl_file(path).events) == 4


def test_invalid_utf8_bytes_are_rejected_not_fatal(tmp_path):
    path = tmp_path / "bad.txt"
    bad = b"1,U\xff1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n"
    path.write_bytes(bad + LINES[0].encode())
    result = ingest_lanl_file(path)
    assert result.rejected[0].reason is RejectReason.ENCODING_ERROR
    assert len(result.events) == 1


def test_empty_file(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")
    result = ingest_lanl_file(path)
    assert (result.lines_read, len(result.events), len(result.rejected)) == (0, 0, 0)


def test_dataset_provenance_is_recorded(tmp_path):
    result = ingest_lanl_file(write(tmp_path, LINES), dataset=DatasetSource.SYNTHETIC)
    assert result.dataset is DatasetSource.SYNTHETIC
    assert {e.dataset for e in result.events} == {DatasetSource.SYNTHETIC}


@pytest.mark.parametrize(
    "kwargs", [{"limit": 0}, {"skip": -1}, {"base_time": datetime(2026, 1, 1)}]
)
def test_invalid_parameters(tmp_path, kwargs):
    with pytest.raises(IngestionError):
        ingest_lanl_file(write(tmp_path, LINES), **kwargs)


def test_missing_file(tmp_path):
    with pytest.raises(IngestionError, match="not found"):
        ingest_lanl_file(tmp_path / "nope.txt")


def test_directory_is_not_a_file(tmp_path):
    with pytest.raises(IngestionError):
        ingest_lanl_file(tmp_path)


def test_corrupt_gzip_raises_ingestion_error(tmp_path):
    path = tmp_path / "auth.txt.gz"
    path.write_bytes(b"this is not gzip data")
    with pytest.raises(IngestionError, match="cannot read"):
        ingest_lanl_file(path)
