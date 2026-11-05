"""IOC extraction from memory forensics data."""
import re
from typing import Dict, List


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+|/(?:[\w.-]+/)+[\w.-]+")
URL_RE = re.compile(r'https?://[^\s<>"\']+')
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
REGISTRY_RE = re.compile(r"(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"']+")
MUTEX_RE = re.compile(r"(?:Global|Local)\\[^\s\"']+")


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract IOCs from free-form text."""
    ips = sorted(set(IP_RE.findall(text)))
    domains = sorted(set(d for d in DOMAIN_RE.findall(text) if "." in d and not d.endswith(".exe")))
    hashes = sorted(set(HASH_RE.findall(text)))
    paths = sorted(set(PATH_RE.findall(text)))
    urls = sorted(set(URL_RE.findall(text)))
    emails = sorted(set(EMAIL_RE.findall(text)))
    registry = sorted(set(REGISTRY_RE.findall(text)))
    mutexes = sorted(set(MUTEX_RE.findall(text)))
    return {
        "ips": ips,
        "domains": domains,
        "hashes": hashes,
        "paths": paths,
        "urls": urls,
        "emails": emails,
        "registry_keys": registry,
        "mutexes": mutexes,
    }
