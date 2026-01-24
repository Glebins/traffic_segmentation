# perf_plot.py
# Зависимости: pandas, matplotlib
# Пример запуска: python perf_plot.py
import os
import argparse
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter, AutoDateLocator

def parse_args():
    p = argparse.ArgumentParser(description="Plot CPU% and RSS(MB) per PID from perf CSV")
    p.add_argument("--file", "-f", default="perf_log.csv", help="Path to CSV file (default: perf_log.csv)")
    p.add_argument("--out", "-o", default="perf_usage_plot.png", help="Output PNG path")
    p.add_argument("--no-exclude-self", action="store_true", help="Do not exclude this script's PID from plots")
    return p.parse_args()

def main():
    args = parse_args()
    FILE_PATH = args.file
    OUT_PNG = args.out
    exclude_self = not args.no_exclude_self
    if not os.path.exists(FILE_PATH):
        print(f"Error: file not found: {FILE_PATH}")
        return

    df = pd.read_csv(FILE_PATH)
    # Expect column 'ts_utc_iso' (ISO timestamp), 'pid', 'name', 'cpu_percent', 'mem_rss_mb'
    if 'ts_utc_iso' not in df.columns:
        # try other common names
        if 'ts' in df.columns:
            df['ts_utc_iso'] = df['ts']
        else:
            raise ValueError("CSV must contain 'ts_utc_iso' column")

    df['ts'] = pd.to_datetime(df['ts_utc_iso'], utc=True, errors='coerce')
    if df['ts'].isnull().all():
        raise ValueError("Parsed timestamps are all NaT. Check ts_utc_iso format.")

    # Ensure numeric columns
    if 'cpu_percent' not in df.columns or 'mem_rss_mb' not in df.columns:
        raise ValueError("CSV must contain 'cpu_percent' and 'mem_rss_mb' columns")
    df['cpu_percent'] = pd.to_numeric(df['cpu_percent'], errors='coerce').fillna(0.0)
    df['mem_rss_mb']  = pd.to_numeric(df['mem_rss_mb'], errors='coerce').fillna(0.0)

    # Optionally exclude this process (analyzer) — useful when you measure live metrics
    if exclude_self:
        try:
            mypid = os.getpid()
            df = df[df['pid'] != mypid]
        except Exception:
            pass

    # Group by PID and sort by time
    groups = {}
    for pid, grp in df.groupby('pid'):
        name_mode = grp['name'].dropna().astype(str).mode()
        proc_name = name_mode.iloc[0] if not name_mode.empty else ""
        groups[int(pid)] = (proc_name, grp.sort_values('ts'))

    # Plotting: two separate plots stacked (CPU% and RSS)
    fig, (ax_cpu, ax_mem) = plt.subplots(2, 1, figsize=(12, 7), sharex=True)
    locator = AutoDateLocator()
    fmt = DateFormatter("%H:%M:%S")

    for pid, (proc_name, grp) in groups.items():
        label = f"{pid} {proc_name}".strip()
        ax_cpu.plot(grp['ts'], grp['cpu_percent'], marker='o', linewidth=1, markersize=4, label=label)
        ax_mem.plot(grp['ts'], grp['mem_rss_mb'], marker='o', linewidth=1, markersize=4, label=label)

    ax_cpu.set_title("CPU % over time (by PID)")
    ax_cpu.set_ylabel("CPU %")
    ax_cpu.grid(True)
    ax_cpu.legend(loc='upper left', bbox_to_anchor=(1.02, 1.0), borderaxespad=0., fontsize='small')

    ax_mem.set_title("RSS memory (MB) over time (by PID)")
    ax_mem.set_ylabel("RSS MB")
    ax_mem.grid(True)
    ax_mem.legend(loc='upper left', bbox_to_anchor=(1.02, 1.0), borderaxespad=0., fontsize='small')

    ax_mem.xaxis.set_major_locator(locator)
    ax_mem.xaxis.set_major_formatter(fmt)
    plt.xticks(rotation=30, ha='right')

    plt.tight_layout(rect=[0,0,0.78,1])
    plt.savefig(OUT_PNG, dpi=150, bbox_inches='tight')
    print(f"Saved {OUT_PNG}")
    plt.show()

if __name__ == "__main__":
    main()
