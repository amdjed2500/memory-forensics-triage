"""Heuristic anomaly detection for memory forensics."""
import re
from typing import List, Dict


def hidden_processes(pslist_pids, psscan_pids):
    """Processes in psscan but not pslist = hidden (rootkit indicator)."""
    hidden = set(psscan_pids) - set(pslist_pids)
    return [{"pid": p, "indicator": "hidden_process", "severity": "high"} for p in hidden]


def suspicious_parent_child(processes):
    """Flag suspicious parent-child relationships (e.g., cmd.exe spawned by winword.exe)."""
    suspicious = []
    suspicious_parents = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"}
    suspicious_children = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
    for p in processes:
        parent = (p.get("parent_name") or "").lower()
        name = (p.get("name") or "").lower()
        if parent in suspicious_parents and name in suspicious_children:
            suspicious.append({"pid": p.get("pid"), "parent": parent, "child": name,
                              "indicator": "suspicious_parent_child", "severity": "high"})
    return suspicious


def rare_listening_ports(connections, common_ports=None):
    """Flag listening ports not in common set."""
    if common_ports is None:
        common_ports = {80, 443, 22, 3389, 445, 139, 135, 53, 123}
    rare = []
    for c in connections:
        port = c.get("local_port")
        state = (c.get("state") or "").lower()
        if state == "listening" and port not in common_ports:
            rare.append({"port": port, "indicator": "rare_listening_port", "severity": "medium"})
    return rare


def process_hollowing(indicators):
    """Placeholder: detect process hollowing via memory-vs-disk image mismatch."""
    return [{"indicator": "process_hollowing", "severity": "high", "detail": i} for i in indicators]


def credential_dumping(processes):
    """Detect credential dumping tools (mimikatz, procdump, etc.)."""
    cred_tools = {"mimikatz.exe", "mimikatz", "procdump.exe", "procdump", "lsass.exe",
                  "wce.exe", "gsecdump.exe", "pwdump.exe", "fgdump.exe"}
    findings = []
    for p in processes:
        name = (p.get("name") or "").lower()
        if name in cred_tools:
            findings.append({"pid": p.get("pid"), "name": name,
                            "indicator": "credential_dumping_tool", "severity": "critical"})
    return findings


def suspicious_network_connections(connections):
    """Flag connections to suspicious ports or external IPs."""
    suspicious_ports = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 1337}
    findings = []
    for c in connections:
        remote_port = c.get("remote_port")
        remote_addr = c.get("remote_addr", "")
        if remote_port in suspicious_ports:
            findings.append({"remote_addr": remote_addr, "remote_port": remote_port,
                            "indicator": "suspicious_remote_port", "severity": "high"})
        # Flag connections to known bad IP ranges (RFC 5737 test ranges)
        if remote_addr.startswith("192.0.2.") or remote_addr.startswith("198.51.100.") or remote_addr.startswith("203.0.113."):
            findings.append({"remote_addr": remote_addr, "indicator": "test_range_ip", "severity": "medium"})
    return findings


def dll_injection(processes):
    """Detect processes with injected DLLs (suspicious modules)."""
    suspicious_dlls = {"kernel32.dll", "ntdll.dll"}  # baseline
    findings = []
    for p in processes:
        modules = p.get("modules", [])
        for mod in modules:
            mod_name = (mod.get("name") or "").lower()
            if mod_name not in suspicious_dlls and mod.get("base_address", 0) > 0x70000000:
                findings.append({"pid": p.get("pid"), "module": mod_name,
                                "indicator": "suspicious_dll_injection", "severity": "medium"})
    return findings
