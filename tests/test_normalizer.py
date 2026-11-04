import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from parsing.normalizer import parse_table, diff_process_lists


SAMPLE = """\
PID    PPID   ImageFileName
4      0      System
348    4      smss.exe
512    4      csrss.exe
"""


def test_parse_table():
    rows = parse_table(SAMPLE)
    assert len(rows) == 3
    assert rows[0]["PID"] == "4"
    assert rows[1]["ImageFileName"] == "smss.exe"


def test_diff_process_lists():
    pslist = "PID    PPID   ImageFileName\n4      0      System\n"
    psscan = "PID    PPID   ImageFileName\n4      0      System\n999    4      hidden.exe\n"
    hidden = diff_process_lists(pslist, psscan)
    assert len(hidden) == 1
    assert hidden[0]["PID"] == "999"