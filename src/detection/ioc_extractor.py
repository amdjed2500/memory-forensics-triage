"""IOC extraction from memory forensics data."""
import re
from typing import Dict, List


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+|/(?:[\w.-]+/)+[\w.-]+")


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract IOCs from free-form text."""
    ips = sorted(set(IP_RE.findall(text)))
    domains = sorted(set(d for d in DOMAIN_RE.findall(text) if "." in d and not d.endswith(".exe")))
    hashes = sorted(set(HASH_RE.findall(text)))
    paths = sorted(set(PATH_RE.findall(text)))
    return {"ips": ips, "domains": domains, "hashes": hashes, "paths": paths}