import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from detection.engine import RuleEngine
from detection.heuristics import hidden_processes, suspicious_parent_child
from detection.ioc_extractor import extract_iocs


def test_rule_engine_match():
    engine = RuleEngine()
    engine.rules = [{"id": "t1", "title": "Hidden", "level": "high", "detection": {"selection": {"pslist_count": 0, "psscan_count": 1}}}]
    findings = engine.evaluate({"pslist_count": 0, "psscan_count": 1})
    assert len(findings) == 1
    assert findings[0]["level"] == "high"


def test_rule_engine_no_match():
    engine = RuleEngine()
    engine.rules = [{"id": "t1", "title": "Hidden", "level": "high", "detection": {"selection": {"pslist_count": 0}}}]
    findings = engine.evaluate({"pslist_count": 5})
    assert len(findings) == 0


def test_hidden_processes():
    res = hidden_processes([4, 512], [4, 512, 999])
    assert len(res) == 1
    assert res[0]["pid"] == 999


def test_ioc_extractor():
    text = "Connect to 192.168.1.5 and evil.com hash d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract_iocs(text)
    assert "192.168.1.5" in iocs["ips"]
    assert "evil.com" in iocs["domains"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["hashes"]