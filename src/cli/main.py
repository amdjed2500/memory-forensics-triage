"""CLI entry point for the memory forensics triage tool."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsing.volatility_runner import VolatilityRunner


def main():
    parser = argparse.ArgumentParser(description="Memory Forensics Triage Tool")
    parser.add_argument("--dump", required=True, help="Path to memory dump")
    parser.add_argument("--profile", default="auto", help="OS profile (auto/windows/linux/mac)")
    parser.add_argument("--vol-path", default="vol", help="Path to Volatility binary")
    parser.add_argument("--output", default="report.md", help="Output report path")
    parser.add_argument("--format", default="markdown", choices=["markdown", "html", "json"])
    parser.add_argument("--plugins", nargs="+", default=["windows.pslist.PsList", "windows.psscan.PsScan", "windows.netscan.NetScan"])
    args = parser.parse_args()

    runner = VolatilityRunner(vol_path=args.vol_path)
    if args.profile == "auto":
        profile = runner.detect_profile(args.dump)
        print(f"[+] Detected profile: {profile}")
    else:
        profile = args.profile

    print(f"[+] Running {len(args.plugins)} plugins on {args.dump}...")
    results = runner.run_plugins(args.dump, args.plugins)
    for plugin, data in results.items():
        rc = data["rc"]
        status = "OK" if rc == 0 else f"FAIL (rc={rc})"
        print(f"  - {plugin}: {status}")
        if data["stderr"]:
            print(f"    stderr: {data['stderr'][:200]}")

    print(f"[+] Report will be written to {args.output} (format: {args.format})")
    # TODO: wire up detection + reporting modules


if __name__ == "__main__":
    main()