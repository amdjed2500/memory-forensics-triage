import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from reporting.generator import ReportGenerator
from reporting.exporter import write_report
import tempfile


def test_render_markdown():
    gen = ReportGenerator()
    ctx = {
        "dump": "mem.raw", "hash": "abc123", "profile": "Win10",
        "date": "2026-11-04", "analyst": "Amdjed",
        "findings": [{"level": "high", "title": "Hidden process", "tags": ["T1014"]}],
        "iocs": {"ips": ["1.2.3.4"], "domains": ["evil.com"], "hashes": [], "paths": []},
        "recommendations": ["Isolate host", "Collect more memory"],
    }
    out = gen.render_markdown(ctx)
    assert "Hidden process" in out
    assert "1.2.3.4" in out
    assert "evil.com" in out


def test_write_report():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "out.md")
        write_report("hello", path)
        assert os.path.exists(path)
        with open(path) as f:
            assert f.read() == "hello"