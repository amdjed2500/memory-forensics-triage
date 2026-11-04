"""Normalize Volatility plugin output into structured data."""
import re
from typing import List, Dict


def parse_table(output: str) -> List[Dict]:
    """Parse Volatility tabular output into list of dicts."""
    lines = [l for l in output.splitlines() if l.strip()]
    if len(lines) < 2:
        return []
    # Find header line (first line with multiple spaces or tabs)
    header_idx = 0
    for i, line in enumerate(lines):
        if "  " in line or "\t" in line:
            header_idx = i
            break
    headers = [h.strip() for h in re.split(r"\s{2,}|\t", lines[header_idx]) if h.strip()]
    rows = []
    for line in lines[header_idx + 1:]:
        if set(line.strip()) <= set("- ") or not line.strip():
            continue
        cols = [c.strip() for c in re.split(r"\s{2,}|\t", line) if c.strip() or True]
        # pad
        while len(cols) < len(headers):
            cols.append("")
        row = dict(zip(headers, cols[:len(headers)]))
        rows.append(row)
    return rows


def diff_process_lists(pslist_out: str, psscan_out: str) -> List[Dict]:
    """Find processes in psscan but not in pslist (hidden processes)."""
    pslist = parse_table(pslist_out)
    psscan = parse_table(psscan_out)
    pslist_pids = {r.get("PID", r.get("Pid", "")) for r in pslist}
    hidden = [r for r in psscan if r.get("PID", r.get("Pid", "")) not in pslist_pids]
    return hidden