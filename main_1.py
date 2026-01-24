#!/usr/bin/env python3
# ETW -> Flow builder -> XGBoost classifier (pure ETW for PID)
# Requires: pywin32, psutil, joblib, numpy, ipaddress

import os
import time
import subprocess
import threading
from datetime import datetime, timezone

import codecs
import win32file, pywintypes
import psutil
import ipaddress
import joblib
import numpy as np

# ---------------- config ----------------
ENGINE_PATH = "./publish/EtwTcp.exe"
PIPE_NAME = r'\\.\pipe\NetMonitorPipe'
LOG_PATH = "flow_log.csv"
CLASS_LIST = ['Normal Traffic', 'DoS', 'DDoS', 'Bots', 'Port Scanning', 'Brute Force', 'Web Attacks']

# model files (must exist)
XGB_MODEL = "xgb_model.joblib"
SCALER = "scaler.joblib"

FLOW_TIMEOUT = 10.0  # seconds

# ---------------- init ----------------
with open(LOG_PATH, "w", encoding="utf-8") as f:
    f.write("timestamp,pid,proc_name,score,label,pkts\n")

xgb_clf = joblib.load(XGB_MODEL)
scaler = joblib.load(SCALER)

# ---------------- local addresses ----------------
def load_local_addresses():
    addrs = set()
    for iface, lst in psutil.net_if_addrs().items():
        for a in lst:
            addr = getattr(a, 'address', None)
            if not addr:
                continue
            if '%' in addr:
                addr = addr.split('%', 1)[0]
            try:
                ip = ipaddress.ip_address(addr)
                addrs.add(ip.exploded if ip.version == 6 else ip.compressed)
            except Exception:
                continue
    return addrs

LOCAL_ADDRS = load_local_addresses()

def classify_ip(ip_str):
    if not ip_str:
        return 'unspecified'
    s = ip_str.split('%', 1)[0]
    try:
        ip = ipaddress.ip_address(s)
    except Exception:
        return 'unspecified'
    if ip.is_loopback:
        return 'loopback'
    if s in LOCAL_ADDRS:
        return 'host'
    if ip.is_link_local:
        return 'linklocal'
    if ip.is_private:
        return 'private'
    return 'public'

def decide_src_dst(local_ip, local_port, remote_ip, remote_port, direction):
    def norm(a): 
        return a.split('%',1)[0] if a else a

    l_ip = norm(local_ip)
    r_ip = norm(remote_ip)
    l_port = str(local_port or '')
    r_port = str(remote_port or '')

    cls_l = classify_ip(l_ip)
    cls_r = classify_ip(r_ip)

    if cls_l == 'loopback' or cls_r == 'loopback' or cls_l == 'unspecified' or cls_r == 'unspecified':
        return None

    host_l = (cls_l == 'host')
    host_r = (cls_r == 'host')

    if not host_l and not host_r:
        return None

    if host_l ^ host_r:
        if direction == "OUT":
            src_ip, src_port = (l_ip, l_port) if host_l else (r_ip, r_port)
            dst_ip, dst_port = (r_ip, r_port) if host_l else (l_ip, l_port)
        else:
            src_ip, src_port = (r_ip, r_port) if host_l else (l_ip, l_port)
            dst_ip, dst_port = (l_ip, l_port) if host_l else (r_ip, r_port)
        return src_ip, src_port, dst_ip, dst_port, 'host-peer'

    if host_l and host_r:
        if direction == "OUT":
            src_ip, src_port = l_ip, l_port
            dst_ip, dst_port = r_ip, r_port
        else:
            src_ip, src_port = r_ip, r_port
            dst_ip, dst_port = l_ip, l_port
        return src_ip, src_port, dst_ip, dst_port, 'host-host'

    return None

# ---------------- ETW pipe reader (yields NetworkPacket-like dict) ----------------
class NetworkPacket:
    def __init__(self, data_line):
        parts = data_line.split('|')
        if len(parts) != 11:
            raise ValueError("Bad packet line: " + data_line)
        self.id = parts[0]
        self.pid = parts[1] if parts[1] else None   # PID only from ETW
        self.proc_name = parts[2]
        self.proto = parts[3]   # 'TCP'/'UDP' etc
        self.direction = parts[4]  # 'OUT'/'IN'
        self.local_ip_raw = parts[5]
        self.local_port_raw = parts[6]
        self.remote_ip_raw = parts[7]
        self.remote_port_raw = parts[8]
        try:
            self.size = int(parts[9])
        except:
            self.size = 0
        self.ts_micros = int(parts[10])
        ds = decide_src_dst(self.local_ip_raw, self.local_port_raw,
                            self.remote_ip_raw, self.remote_port_raw,
                            self.direction)
        if ds is None:
            self.valid = False
        else:
            self.valid = True
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.reason = ds
        p = self.proto.upper()
        if p.startswith("TCP"): self.proto_num = 6
        elif p.startswith("UDP"): self.proto_num = 17
        elif p.startswith("ICMP"): self.proto_num = 1
        else:
            try:
                self.proto_num = int(self.proto)
            except:
                self.proto_num = 0
    def timestamp(self):
        return self.ts_micros / 1_000_000.0

def start_capture_engine(engine_path=ENGINE_PATH, pipe_name=PIPE_NAME):
    if not os.path.exists(engine_path):
        raise FileNotFoundError(f"ETW engine not found: {engine_path}")
    subprocess.Popen([engine_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
    while True:
        try:
            handle = win32file.CreateFile(
                pipe_name,
                win32file.GENERIC_READ,
                0, None,
                win32file.OPEN_EXISTING,
                0, None
            )
            break
        except pywintypes.error:
            time.sleep(0.5)

    decoder = codecs.getincrementaldecoder('utf-8')()
    buffer = ""
    while True:
        try:
            resp = win32file.ReadFile(handle, 64*1024)
            chunk = resp[1]
            if not chunk:
                time.sleep(0.01)
                continue
            text = decoder.decode(chunk)
            if text:
                buffer += text
                while "\r\n" in buffer:
                    line, buffer = buffer.split("\r\n", 1)
                    if '|' in line:
                        try:
                            pkt = NetworkPacket(line)
                        except Exception:
                            continue
                        if pkt.valid:
                            yield pkt
        except Exception as e:
            print(f"The connection aborted: {e}")
            break
        except KeyboardInterrupt:
            print("Graceful end")
            break

# ---------------- flows ----------------
flows = {}
flows_lock = threading.Lock()
packet_counter = 0

def canonical_key(src_ip, src_port, dst_ip, dst_port, proto):
    try:
        a_ip = ipaddress.ip_address(src_ip)
        b_ip = ipaddress.ip_address(dst_ip)
        a_val = (int(a_ip), int(src_port or 0), a_ip.version)
        b_val = (int(b_ip), int(dst_port or 0), b_ip.version)
    except Exception:
        a_val = (str(src_ip), int(src_port or 0), 4)
        b_val = (str(dst_ip), int(dst_port or 0), 4)
    if a_val <= b_val:
        return (src_ip, int(src_port or 0), dst_ip, int(dst_port or 0), int(proto)), True
    else:
        return (dst_ip, int(dst_port or 0), src_ip, int(src_port or 0), int(proto)), False

def update_flow_from_packet(pkt: NetworkPacket):
    global packet_counter
    packet_counter += 1
    t = pkt.timestamp()
    length = pkt.size or 0
    proto = pkt.proto_num

    key, is_forward = canonical_key(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, proto)

    with flows_lock:
        flow = flows.get(key)
        if flow is None:
            pid = None
            proc_name = None
            try:
                pid = int(pkt.pid) if pkt.pid else None   # ONLY from ETW
                proc_name = pkt.proc_name
            except:
                pid = None
                proc_name = None
            flow = {
                "pid": pid,
                "proc_name": proc_name,
                "start_time": t,
                "last_time": t,
                "fwd_pkts": 0,
                "bwd_pkts": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "fwd_sizes": [],
                "bwd_sizes": [],
                "all_sizes": [],
                "fwd_ts": [],
                "bwd_ts": [],
                "all_ts": [],
                "fwd_hdr_lens": [],
                "bwd_hdr_lens": [],
                "fwd_init_win": None,
                "bwd_init_win": None,
                "fwd_psh": 0,
                "bwd_psh": 0,
                "fin_count": 0,
                "ack_count": 0,
                "fwd_act_data_pkts": 0,
                "fwd_min_seg_size": None,
                "dst_port": key[3],
                "reason": getattr(pkt, "reason", None)
            }
            flows[key] = flow

        flow["last_time"] = t
        direction = "fwd" if is_forward else "bwd"

        flow["all_sizes"].append(length)
        flow["all_ts"].append(t)

        if direction == "fwd":
            flow["fwd_pkts"] += 1
            flow["fwd_bytes"] += length
            flow["fwd_sizes"].append(length)
            flow["fwd_ts"].append(t)
        else:
            flow["bwd_pkts"] += 1
            flow["bwd_bytes"] += length
            flow["bwd_sizes"].append(length)
            flow["bwd_ts"].append(t)

        try:
            ip_hdr_len = 40 if ipaddress.ip_address(pkt.src_ip).version == 6 else 20
        except:
            ip_hdr_len = 20

        if proto == 6:
            tcp_hdr_len = 20
            hdr_len = ip_hdr_len + tcp_hdr_len
            payload_len = max(0, length - hdr_len)
            if direction == "fwd" and payload_len > 0:
                flow["fwd_act_data_pkts"] += 1
                if flow["fwd_min_seg_size"] is None or payload_len < flow["fwd_min_seg_size"]:
                    flow["fwd_min_seg_size"] = payload_len
        elif proto == 17:
            udp_hdr_len = 8
            hdr_len = ip_hdr_len + udp_hdr_len
        elif proto == 1:
            icmp_hdr_len = 8
            hdr_len = ip_hdr_len + icmp_hdr_len
        else:
            hdr_len = ip_hdr_len

        if direction == "fwd":
            flow["fwd_hdr_lens"].append(hdr_len)
        else:
            flow["bwd_hdr_lens"].append(hdr_len)

    return

# ---------------- compute features & finalize ----------------
def compute_features(flow):
    duration = max(1e-6, flow["last_time"] - flow["start_time"])
    fwd_pkts = flow["fwd_pkts"]
    bwd_pkts = flow["bwd_pkts"]
    total_pkts = fwd_pkts + bwd_pkts
    fwd_bytes = flow["fwd_bytes"]
    bwd_bytes = flow["bwd_bytes"]
    total_bytes = fwd_bytes + bwd_bytes

    fwd_sizes = flow["fwd_sizes"]
    bwd_sizes = flow["bwd_sizes"]
    all_sizes = flow["all_sizes"]

    fwd_ts = flow["fwd_ts"]
    bwd_ts = flow["bwd_ts"]
    all_ts = flow["all_ts"]

    def mean_std(data):
        if not data:
            return 0.0, 0.0
        m = sum(data) / len(data)
        s2 = sum((x - m) ** 2 for x in data) / len(data)
        return m, s2 ** 0.5

    def min_max(data):
        if not data:
            return 0, 0
        return min(data), max(data)

    iats = [j - i for i, j in zip(sorted(all_ts), sorted(all_ts)[1:])] if len(all_ts) > 1 else []
    fwd_iats = [j - i for i, j in zip(sorted(fwd_ts), sorted(fwd_ts)[1:])] if len(fwd_ts) > 1 else []
    bwd_iats = [j - i for i, j in zip(sorted(bwd_ts), sorted(bwd_ts)[1:])] if len(bwd_ts) > 1 else []

    fwd_hdrs = flow["fwd_hdr_lens"]
    bwd_hdrs = flow["bwd_hdr_lens"]

    dst_port = flow.get("dst_port", 0)

    fwd_min, fwd_max = min_max(fwd_sizes)
    fwd_mean, fwd_std = mean_std(fwd_sizes)

    bwd_min, bwd_max = min_max(bwd_sizes)
    bwd_mean, bwd_std = mean_std(bwd_sizes)

    feature_flow_bytes_s = total_bytes / duration
    feature_flow_pkts_s = (fwd_pkts + bwd_pkts) / duration

    iat_min, iat_max = min_max(iats)
    iat_mean, iat_std = mean_std(iats)

    fwd_iat_total = sum(fwd_iats) if fwd_iats else 0.0
    fwd_iat_min, fwd_iat_max = min_max(fwd_iats)
    fwd_iat_mean, fwd_iat_std = mean_std(fwd_iats)

    bwd_iat_total = sum(bwd_iats) if bwd_iats else 0.0
    bwd_iat_min, bwd_iat_max = min_max(bwd_iats)
    bwd_iat_mean, bwd_iat_std = mean_std(bwd_iats)

    fwd_hdr_total = sum(fwd_hdrs) if fwd_hdrs else 0
    bwd_hdr_total = sum(bwd_hdrs) if bwd_hdrs else 0

    feature_fwd_pkts_s = fwd_pkts / duration if duration > 0 else 0.0
    feature_bwd_pkts_s = bwd_pkts / duration if duration > 0 else 0.0

    all_min, all_max = min_max(all_sizes)
    all_mean, all_std = mean_std(all_sizes)
    all_var = all_std ** 2

    fin_count = flow.get("fin_count", 0)
    psh_count = flow.get("fwd_psh", 0) + flow.get("bwd_psh", 0)
    ack_count = flow.get("ack_count", 0)

    avg_pkt_size = total_bytes / (fwd_pkts + bwd_pkts) if (fwd_pkts + bwd_pkts) > 0 else 0.0
    subflow_fwd_bytes = fwd_bytes

    init_win_fwd = flow.get("fwd_init_win", 0) or 0
    init_win_bwd = flow.get("bwd_init_win", 0) or 0

    act_data_pkt_fwd = flow.get("fwd_act_data_pkts", 0)
    min_seg_size_forward = flow.get("fwd_min_seg_size", 0) or 0

    active_iats = [x for x in iats if x < 0.5]
    act_min, act_max = min_max(active_iats)
    act_mean, _ = mean_std(active_iats)

    idle_iats = [x for x in iats if x >= 0.5]
    idle_min, idle_max = min_max(idle_iats)
    idle_mean, _ = mean_std(idle_iats)

    features = [
        dst_port,
        duration,
        fwd_pkts,
        fwd_bytes,
        fwd_max,
        fwd_min,
        fwd_mean,
        fwd_std,
        bwd_max,
        bwd_min,
        bwd_mean,
        bwd_std,
        feature_flow_bytes_s,
        feature_flow_pkts_s,
        iat_mean,
        iat_std,
        iat_max,
        iat_min,
        fwd_iat_total,
        fwd_iat_mean,
        fwd_iat_std,
        fwd_iat_max,
        fwd_iat_min,
        bwd_iat_total,
        bwd_iat_mean,
        bwd_iat_std,
        bwd_iat_max,
        bwd_iat_min,
        fwd_hdr_total,
        bwd_hdr_total,
        feature_fwd_pkts_s,
        feature_bwd_pkts_s,
        all_min,
        all_max,
        all_mean,
        all_std,
        all_var,
        fin_count,
        psh_count,
        ack_count,
        avg_pkt_size,
        subflow_fwd_bytes,
        init_win_fwd,
        init_win_bwd,
        act_data_pkt_fwd,
        min_seg_size_forward,
        act_mean,
        act_max,
        act_min,
        idle_mean,
        idle_max,
        idle_min
    ]
    return features

def process_and_finalize(key, flow):
    features = compute_features(flow)
    x = np.array(features, dtype=np.float32).reshape(1, -1)
    x_scaled = scaler.transform(x)
    probs = xgb_clf.predict_proba(x_scaled)

    pid = flow.get("pid")
    proc_name = flow.get("proc_name")
    if not proc_name:
        try:
            proc_name = psutil.Process(pid).name()
        except Exception:
            proc_name = "Unknown_ps"

    total_pkts = flow.get("fwd_pkts", 0) + flow.get("bwd_pkts", 0)
    label = CLASS_LIST[np.argmax(probs)]
    score = probs.max()
    safe_score = probs[0][0]
    print(f"[{time.strftime('%H:%M:%S')}] Flow {key}: proc={proc_name}, score={score:.3f}, label={label}, pkts={total_pkts}")

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts},{pid or ''},{proc_name},{safe_score:.6f},{label},{total_pkts}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)

# ---------------- timeout watcher ----------------
def timeout_watcher():
    while True:
        now = time.time()
        timed_out = []
        with flows_lock:
            for key, flow in list(flows.items()):
                if now - flow["last_time"] > FLOW_TIMEOUT:
                    timed_out.append((key, flows.pop(key)))
        for key, flow in timed_out:
            process_and_finalize(key, flow)
        time.sleep(1.0)

threading.Thread(target=timeout_watcher, daemon=True).start()

# ---------------- main loop ----------------
def main():
    for pkt in start_capture_engine(ENGINE_PATH, PIPE_NAME):
        try:
            update_flow_from_packet(pkt)
        except Exception:
            continue

if __name__ == "__main__":
    main()
