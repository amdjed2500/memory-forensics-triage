"""CLI entry point for the memory forensics triage tool."""
import argparse
import os
import sys
import hashlib
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsing.volatility_runner import VolatilityRunner
from parsing.normalizer import parse_table
from detection.engine import RuleEngine
from detection.heuristics import hidden_processes
from detection.ioc_extractor import extract_iocs
from reporting.generator import ReportGenerator
from reporting.exporter import write_report

DEFAULT_PLUGINS = ["windows.pslist.PsList", "windows.psscan.PsScan", "windows.netscan.NetScan"]
DEFAULT_RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detection", "rules")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Memory Forensics Triage Tool")
    parser.add_argument("--dump", required=True, help="Path to memory dump")
    parser.add_argument("--profile", default="auto", help="OS profile (auto/windows/linux/mac)")
    parser.add_argument("--vol-path", default="vol", help="Path to Volatility binary")
    parser.add_argument("--output", default="report.md", help="Output report path")
    parser.add_argument("--format", default="markdown", choices=["markdown", "html", "json"])
    parser.add_argument("--plugins", nargs="+", default=DEFAULT_PLUGINS)
    parser.add_argument("--rules", default=DEFAULT_RULES, help="Detection rules directory")
    args = parser.parse_args()

    runner = VolatilityRunner(vol_path=args.vol_path)
    if args.profile == "auto":
        profile = runner.detect_profile(args.dump)
        print(f"[+] Detected profile: {profile}")
    else:
        profile = args.profile

    print(f"[+] Hashing dump...")
    dump_hash = sha256_file(args.dump)

    print(f"[+] Running {len(args.plugins)} plugins on {args.dump}...")
    results = runner.run_plugins(args.dump, args.plugins)

    pslist_out = results.get("windows.pslist.PsList", {}).get("stdout", "")
    psscan_out = results.get("windows.psscan.PsScan", {}).get("stdout", "")
    netscan_out = results.get("windows.netscan.NetScan", {}).get("stdout", "")

    pslist_rows = parse_table(pslist_out)
    psscan_rows = parse_table(psscan_out)

    pslist_pids = [r.get("PID", r.get("Pid", "")) for r in pslist_rows]
    psscan_pids = [r.get("PID", r.get("Pid", "")) for r in psscan_rows]

    engine = RuleEngine(rules_dir=args.rules)
    data = {"pslist_count": len(pslist_rows), "psscan_count": len(psscan_rows)}
    findings = engine.evaluate(data)
    findings += hidden_processes(pslist_pids, psscan_pids)

    all_text = "\n".join(r.get("stdout", "") for r in results.values())
    iocs = extract_iocs(all_text)

    recommendations = []
    if findings:
        recommendations.append("Isolate the affected host from the network.")
        recommendations.append("Collect additional forensic artifacts (disk, logs).")
    else:
        recommendations.append("No anomalies detected. Continue routine monitoring.")

    context = {
        "dump": os.path.basename(args.dump),
        "hash": dump_hash,
        "profile": profile,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "analyst": "Amdjed",
        "findings": findings,
        "iocs": iocs,
        "recommendations": recommendations,
    }

    gen = ReportGenerator()
    content = gen.render_markdown(context)
    write_report(content, args.output)
    print(f"[+] Report written to {args.output}")
    print(f"[+] Findings: {len(findings)} | IOCs: {sum(len(v) for v in iocs.values())}")


if __name__ == "__main__":
    main()