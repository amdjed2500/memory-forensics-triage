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