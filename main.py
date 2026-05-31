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
from win11toast import toast

from get_result import HybridSecuritySystem

# ---------------- config ----------------
ENGINE_PATH = "./publish/EtwTcp.exe"
PIPE_NAME = r'\\.\pipe\NetMonitorPipe'
LOG_PATH = "flow_log_test.csv"
FEATURES_CSV = "flow_features_test.csv"
CLASS_LIST = ['Normal Traffic', 'DoS', 'DDoS', 'Bots', 'Port Scanning', 'Brute Force', 'Web Attacks']

XGB_MODEL = "xgb_model.joblib"
SCALER = "scaler.joblib"
ACCUMULATION_STATE_FILE = "accumulation_state.txt"

FLOW_TIMEOUT = 20
MAX_FLOW_PKTS = 3000

# ---------------- sanity load models ----------------
xgb_clf = None
scaler = None
if os.path.exists(XGB_MODEL) and os.path.exists(SCALER):
    xgb_clf = joblib.load(XGB_MODEL)
    scaler = joblib.load(SCALER)
else:
    xgb_clf = None
    scaler = None

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
    l_port = int(local_port or 0)
    r_port = int(remote_port or 0)

    cls_l = classify_ip(l_ip)
    cls_r = classify_ip(r_ip)

    if cls_l == 'loopback' or cls_r == 'loopback':
        return None

    host_l = (cls_l == 'host')
    host_r = (cls_r == 'host')

    if not host_l and not host_r:
        return None
    
    if host_l and not host_r:
        src_ip, src_port = l_ip, l_port
        dst_ip, dst_port = r_ip, r_port
        return src_ip, src_port, dst_ip, dst_port, 'host-peer'

    if host_r and not host_l:
        src_ip, src_port = r_ip, r_port
        dst_ip, dst_port = l_ip, l_port
        return src_ip, src_port, dst_ip, dst_port, 'host-peer'
    
    return l_ip, l_port, r_ip, r_port, 'host-host'

# ---------------- ETW pipe reader (NetworkPacket) ----------------
class NetworkPacket:
    def __init__(self, data_line):
        parts = data_line.split('|')
        if len(parts) != 11:
            raise ValueError("Bad packet line: " + data_line)
        self.id = parts[0]
        self.pid = None
        try:
            self.pid = int(parts[1]) if parts[1] not in ('', 'None') else None
        except:
            self.pid = None
        self.proc_name = parts[2] or None
        self.proto = parts[3]
        self.direction = parts[4]
        self.local_ip_raw = parts[5]
        self.local_port_raw = parts[6]
        self.remote_ip_raw = parts[7]
        self.remote_port_raw = parts[8]
        try:
            self.size = int(parts[9])
        except:
            self.size = 0
        try:
            self.ts_micros = int(parts[10])
        except:
            self.ts_micros = int(time.time() * 1_000_000)

        ds = decide_src_dst(self.local_ip_raw, self.local_port_raw,
                            self.remote_ip_raw, self.remote_port_raw,
                            self.direction)
        if ds is None:
            self.valid = False
            return
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


def read_accumulation_state():
    try:
        if os.path.exists(ACCUMULATION_STATE_FILE):
            with open(ACCUMULATION_STATE_FILE, 'r', encoding='utf-8') as sf:
                return sf.read().strip().lower() == 'on'
    except Exception:
        pass
    return False


def set_accumulation_state(enabled: bool):
    try:
        with open(ACCUMULATION_STATE_FILE, 'w', encoding='utf-8') as sf:
            sf.write('on' if enabled else 'off')
    except Exception:
        pass


def start_capture_engine(engine_path=ENGINE_PATH, pipe_name=PIPE_NAME):
    if engine_path and os.path.exists(engine_path):
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
                time.sleep(0.01); continue
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
        except KeyboardInterrupt:
            print("Graceful stop")
            break
        except Exception:
            break

# ---------------- flows (PID, src_ip, dst_ip, proto) ----------------
flows = {}
flows_lock = threading.Lock()

def make_flow_key(pid, src_ip, dst_ip, proto):
    pid_key = int(pid) if pid else 0
    return (pid_key, src_ip, dst_ip, int(proto))

def update_flow_from_packet(pkt: NetworkPacket):
    t = pkt.timestamp()
    length = pkt.size or 0
    proto = pkt.proto_num
    pid = pkt.pid or 0

    key = make_flow_key(pid, pkt.src_ip, pkt.dst_ip, proto)
    remote_port = int(pkt.remote_port_raw or 0) if hasattr(pkt, 'remote_port_raw') else int(pkt.dst_port or 0)

    with flows_lock:
        flow = flows.get(key)
        if flow is None:
            flow = {
                "pid": pid,
                "proc_name": pkt.proc_name,
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
                "first_dst_port": remote_port,
                "dst_port": remote_port,
                "reason": pkt.reason,
                "fwd_ip_start": pkt.src_ip,
                "fwd_port_start": pkt.src_port
            }
            flows[key] = flow

        flow["last_time"] = t

        if pkt.src_ip == flow["fwd_ip_start"] and pkt.src_port == flow["fwd_port_start"]:
            is_forward = True
        else:
            is_forward = False
        
        flow["all_sizes"].append(length)
        flow["all_ts"].append(t)
        if is_forward:
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
            if payload_len > 0:
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

        if is_forward:
            flow["fwd_hdr_lens"].append(hdr_len)
        else:
            flow["bwd_hdr_lens"].append(hdr_len)

        total_packets = flow["fwd_pkts"] + flow["bwd_pkts"]

        if total_packets >= MAX_FLOW_PKTS:
            finished_flow = flows.pop(key)
            process_and_finalize(key, finished_flow)

    return

# ---------------- compute features & finalize ----------------
def compute_features(flow):
    duration_s = max(1e-6, flow["last_time"] - flow["start_time"])
    duration_us = duration_s * 1_000_000.0

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
        s2 = sum((x - m) ** 2 for x in data) / len(data) if len(data) > 1 else 0.0
        return m, s2 ** 0.5

    def min_max(data):
        if not data:
            return 0.0, 0.0
        return float(min(data)), float(max(data))

    sorted_all_ts = sorted(all_ts)
    iats_s = [j - i for i, j in zip(sorted_all_ts, sorted_all_ts[1:])] if len(sorted_all_ts) > 1 else []
    fwd_iats_s = [j - i for i, j in zip(sorted(fwd_ts), sorted(fwd_ts)[1:])] if len(fwd_ts) > 1 else []
    bwd_iats_s = [j - i for i, j in zip(sorted(bwd_ts), sorted(bwd_ts)[1:])] if len(bwd_ts) > 1 else []

    iats = [x * 1_000_000.0 for x in iats_s]
    fwd_iats = [x * 1_000_000.0 for x in fwd_iats_s]
    bwd_iats = [x * 1_000_000.0 for x in bwd_iats_s]

    fwd_hdrs = flow["fwd_hdr_lens"]
    bwd_hdrs = flow["bwd_hdr_lens"]

    dst_port = flow.get("first_dst_port", 0)

    fwd_min, fwd_max = min_max(fwd_sizes)
    fwd_mean, fwd_std = mean_std(fwd_sizes)

    bwd_min, bwd_max = min_max(bwd_sizes)
    bwd_mean, bwd_std = mean_std(bwd_sizes)

    flow_bytes_s = total_bytes / duration_s
    flow_pkts_s = total_pkts / duration_s

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

    fwd_pkts_s = fwd_pkts / duration_s if duration_s > 0 else 0.0
    bwd_pkts_s = bwd_pkts / duration_s if duration_s > 0 else 0.0

    all_min, all_max = min_max(all_sizes)
    all_mean, all_std = mean_std(all_sizes)
    all_var = all_std ** 2

    fin_count = flow.get("fin_count", 0)
    psh_count = flow.get("fwd_psh", 0) + flow.get("bwd_psh", 0)
    ack_count = flow.get("ack_count", 0)

    avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0.0
    subflow_fwd_bytes = fwd_bytes

    init_win_fwd = flow.get("fwd_init_win", 0) or 0
    init_win_bwd = flow.get("bwd_init_win", 0) or 0

    act_data_pkt_fwd = flow.get("fwd_act_data_pkts", 0)
    min_seg_size_forward = flow.get("fwd_min_seg_size", 0) or 0

    idle_threshold = 1.0
    active_durations = []
    idle_iats = []
    if len(sorted_all_ts) > 1:
        current_burst_start = sorted_all_ts[0]
        for idx in range(1, len(sorted_all_ts)):
            iat = sorted_all_ts[idx] - sorted_all_ts[idx - 1]
            if iat < idle_threshold:
                pass
            else:
                active_duration = sorted_all_ts[idx - 1] - current_burst_start
                if active_duration > 0:
                    active_durations.append(active_duration)
                idle_iats.append(iat)
                current_burst_start = sorted_all_ts[idx]
        active_duration = sorted_all_ts[-1] - current_burst_start
        if active_duration > 0:
            active_durations.append(active_duration)

    if active_durations:
        act_mean = sum(active_durations) / len(active_durations) * 1_000_000
        act_min = min(active_durations) * 1_000_000
        act_max = max(active_durations) * 1_000_000
    else:
        act_mean = 0.0
        act_min = 0
        act_max = 0

    if idle_iats:
        idle_mean = sum(idle_iats) / len(idle_iats) * 1_000_000
        idle_min = min(idle_iats) * 1_000_000
        idle_max = max(idle_iats) * 1_000_000
    else:
        idle_mean = 0.0
        idle_min = 0
        idle_max = 0
    
    features = [
        dst_port,
        duration_us,
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
        flow_bytes_s,
        flow_pkts_s,
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
        fwd_pkts_s,
        bwd_pkts_s,
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
    total_pkts = flow.get("fwd_pkts", 0) + flow.get("bwd_pkts", 0)
    features = compute_features(flow)

    accumulation_enabled = read_accumulation_state()

    pid = flow.get("pid", 0)
    proc_name = flow.get("proc_name") or "Unknown"

    label = "N/A"
    score = 0.0
    safe_score = 0.0
    probs = None
    if accumulation_enabled:
        result = {
            "status": "ACCUMULATION",
            "threat_prob": 0.0,
            "anomaly_consensus": 0.0,
            "details": {}
        }
    else:
        if xgb_clf is not None and scaler is not None:
            try:
                x = np.array(features, dtype=np.float32).reshape(1, -1)

                x_scaled = scaler.transform(x)
                probs = xgb_clf.predict_proba(x_scaled)
                label = CLASS_LIST[np.argmax(probs)]
                score = float(probs.max())
                safe_score = float(probs[0][0])
            except Exception as e:
                label = "Error"
                score = 0.0
                safe_score = 0.0
                print(f'ERROR OCCURED: {e}')

        detector = HybridSecuritySystem()
        result = detector.instance_analyze_flow(features)

    if 'HIGH' in result['status'] or 'CRITICAL' in result['status']:
        title = "Net monitoring: Suspicious packet"

        alert_message = f"Process name: {proc_name}\nVerdict: {result['status']} (Prob: {result['threat_prob']:.2f})"

        try:
            toast(title, alert_message, duration='long', audio='ms-winsoundevent:Notification.Looping.Alarm')
        except:
            pass

    print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] Flow {key}: proc={proc_name}, pid={pid}, label={label}, score={score:.3f}, pkts={total_pkts}")

    if not accumulation_enabled and proc_name == 'python' and probs is not None:
        print(x.tolist(), probs, sep='\n')

    ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    if accumulation_enabled:
        line = f"{ts},{pid or ''},{proc_name},{total_pkts},,{result['status']},,,\n"
    else:
        line = (
            f"{ts},{pid or ''},{proc_name},{total_pkts},{result['threat_prob']:.6f},"
            f"{result['status']},{score:.6f},{label},{result['anomaly_consensus']:.6f}\n"
        )
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)

    if read_accumulation_state():
        try:
            import csv, os

            write_header = not os.path.exists(FEATURES_CSV)

            if write_header:
                feat_count = len(features)
                header = [
                    "ts_utc",
                    "flow_key_pid",
                    "flow_src_ip",
                    "flow_dst_ip",
                    "flow_proto",
                    "pid",
                    "proc_name",
                    "label",
                    "score",
                    "total_pkts"
                ]

                header += [f"feat_{i}" for i in range(feat_count)]

                with open(FEATURES_CSV, "w", encoding="utf-8", newline='') as hf:
                    writer = csv.writer(hf)
                    writer.writerow(header)

            try:
                k_pid = key[0]
                k_src = key[1]
                k_dst = key[2]
                k_proto = key[3]
            except Exception:
                k_pid = ""
                k_src = ""
                k_dst = ""
                k_proto = ""

            row = [
                datetime.utcnow().isoformat(timespec="microseconds") + "Z",
                k_pid,
                k_src,
                k_dst,
                k_proto,
                pid or "",
                proc_name,
                label,
                f"{score:.6f}",
                total_pkts
            ]

            row += ["" if v is None else v for v in features]

            with open(FEATURES_CSV, "a", encoding="utf-8", newline='') as hf:
                writer = csv.writer(hf)
                writer.writerow(row)
        except Exception as e:
            print(f"Failed to write features CSV: {e}")
    else:
        pass

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
            try:
                process_and_finalize(key, flow)
            except Exception:
                pass
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
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        f.write("ts,PID,process,num_of_packets,threat probability,status,xgb_score,xgb_label,anomaly_score\n")
    if not os.path.exists(ACCUMULATION_STATE_FILE):
        set_accumulation_state(False)
    main()