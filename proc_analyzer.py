#!/usr/bin/env python3
# perf_monitor.py
# Usage: python perf_monitor.py [--interval 1.0] [--out perf_log.csv] [--targets "main.py;EtwTcp.exe"]

import os
import time
import argparse
from datetime import datetime
import psutil
import csv

MY_PID = os.getpid()

def parse_args():
    p = argparse.ArgumentParser(description="Process performance monitor (exclude self).")
    p.add_argument("--interval", "-i", type=float, default=1.0, help="Sampling interval in seconds")
    p.add_argument("--out", "-o", type=str, default="perf_log.csv", help="Output CSV file")
    p.add_argument("--targets", "-t", type=str, default="python.exe;EtwTcp.exe",
                   help="Semicolon-separated substrings to match process cmdline/name (default: main.py;EtwTcp.exe)")
    p.add_argument("--warmup", type=float, default=0.1, help="Initial CPU warmup interval (seconds)")
    return p.parse_args()

def target_matcher_from_string(s):
    parts = [x.strip().lower() for x in s.split(";") if x.strip()]
    def is_target(p):
        try:
            if p.pid == MY_PID:
                return False
            cmd = " ".join(p.cmdline() or []).lower()
            name = (p.name() or "").lower()
            for pat in parts:
                if pat in cmd or pat in name:
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        return False
    return is_target

def find_target_procs(matcher):
    """Return dict pid -> psutil.Process for matching processes (excluding monitor)."""
    res = {}
    for p in psutil.process_iter(["pid","name","cmdline","create_time"]):
        try:
            if matcher(p):
                res[p.pid] = p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return res

def ensure_csv_header(path):
    header = ["ts_utc_iso", "pid", "name", "cmdline", "create_time",
              "cpu_percent", "mem_rss_mb", "mem_vms_mb", "mem_percent",
              "num_threads", "io_read_bytes", "io_write_bytes"]
    newfile = not os.path.exists(path)
    f = open(path, "a", newline="", encoding="utf-8")
    writer = csv.writer(f)
    if newfile:
        writer.writerow(header)
        f.flush()
    return f, writer

def sample_process(p):
    """Return dict of sampled metrics for psutil.Process p"""
    out = {}
    try:
        # cpu_percent must be called twice separated by interval to be meaningful
        cpu = p.cpu_percent(interval=None)
        mem = p.memory_info()
        io = None
        try:
            io = p.io_counters()
        except Exception:
            io = None
        out = {
            "pid": p.pid,
            "name": p.name(),
            "cmdline": " ".join(p.cmdline() or []),
            "create_time": datetime.utcfromtimestamp(p.create_time()).isoformat() if p.create_time() else "",
            "cpu_percent": cpu,
            "mem_rss_mb": (mem.rss / (1024*1024)) if mem else 0.0,
            "mem_vms_mb": (mem.vms / (1024*1024)) if mem else 0.0,
            "mem_percent": p.memory_percent() if hasattr(p, "memory_percent") else 0.0,
            "num_threads": p.num_threads() if hasattr(p, "num_threads") else 0,
            "io_read_bytes": io.read_bytes if io is not None else 0,
            "io_write_bytes": io.write_bytes if io is not None else 0
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    return out

def main():
    args = parse_args()
    matcher = target_matcher_from_string(args.targets)
    out_f, csv_writer = ensure_csv_header(args.out)

    # Warmup: find any targets and call cpu_percent once so next sample is valid
    print(f"[{datetime.utcnow().isoformat()}] Perf monitor starting. My PID={MY_PID}. Looking for targets: {args.targets}")
    initial = find_target_procs(matcher)
    for p in initial.values():
        try:
            p.cpu_percent(None)
        except Exception:
            pass
    time.sleep(args.warmup)

    try:
        while True:
            ts = datetime.utcnow().isoformat()
            procs = find_target_procs(matcher)
            # If none found, still record a heartbeat with empty row
            if not procs:
                print(f"{ts} - no target processes found (will retry).")
            for pid, p in list(procs.items()):
                sample = sample_process(p)
                if sample is None:
                    continue
                row = [
                    ts,
                    sample["pid"],
                    sample["name"],
                    sample["cmdline"],
                    sample["create_time"],
                    f"{sample['cpu_percent']:.1f}",
                    f"{sample['mem_rss_mb']:.6f}",
                    f"{sample['mem_vms_mb']:.6f}",
                    f"{sample['mem_percent']:.3f}",
                    sample['num_threads'],
                    sample['io_read_bytes'],
                    sample['io_write_bytes']
                ]
                csv_writer.writerow(row)
                out_f.flush()
                print(",".join(map(str, row)))
            # sleep interval (we already called cpu_percent earlier non-blocking)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Stopping monitor.")
    finally:
        try:
            out_f.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
