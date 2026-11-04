"""Volatility 3 plugin runner."""
import subprocess
import json
import os
from pathlib import Path


class VolatilityRunner:
    def __init__(self, vol_path="vol", profile=None):
        self.vol_path = vol_path
        self.profile = profile

    def run_plugin(self, dump_path, plugin, extra_args=None):
        """Run a Volatility 3 plugin and return raw output."""
        cmd = [self.vol_path, "-f", str(dump_path), plugin]
        if self.profile:
            cmd += ["--profile", self.profile]
        if extra_args:
            cmd += extra_args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Plugin timed out", 1
        except FileNotFoundError:
            return "", f"Volatility not found at {self.vol_path}", 127

    def run_plugins(self, dump_path, plugins):
        """Run multiple plugins, return dict of plugin -> output."""
        results = {}
        for p in plugins:
            out, err, rc = self.run_plugin(dump_path, p)
            results[p] = {"stdout": out, "stderr": err, "rc": rc}
        return results

    def detect_profile(self, dump_path):
        """Auto-detect OS profile from dump."""
        out, err, rc = self.run_plugin(dump_path, "windows.info.Info")
        if rc == 0 and out:
            return "windows"
        out, err, rc = self.run_plugin(dump_path, "linux.pslist.PsList")
        if rc == 0 and out:
            return "linux"
        out, err, rc = self.run_plugin(dump_path, "mac.pslist.PsList")
        if rc == 0 and out:
            return "mac"
        return "unknown"