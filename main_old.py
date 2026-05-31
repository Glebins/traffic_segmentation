import threading
import time

import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP
import psutil
import joblib
from threat_analysis import HybridSecuritySystem
import ipaddress

import os
LOG_PATH = "flow_log.csv"
# CSV now includes detector status, threat probability and anomaly consensus when available
with open(LOG_PATH, "w", encoding="utf-8") as f:
    f.write("timestamp,pid,proc_name,score,label,status,threat_prob,anomaly_consensus\n")

CLASS_LIST = ['Normal Traffic', 'DoS', 'DDoS', 'Bots', 'Port Scanning', 'Brute Force', 'Web Attacks']

xgb_clf = joblib.load("xgb_model.joblib")
scaler = joblib.load("scaler.joblib")

# Lazy-initialized hybrid detector (may be None if model files missing)
_detector = None
def get_detector(models_dir="."):
    global _detector
    if _detector is None:
        try:
            _detector = HybridSecuritySystem(models_dir=models_dir)
        except Exception:
            _detector = None
    return _detector

# Порог подозрительности (пример)
SUSPICIOUS_THRESHOLD = 0.5

# Таймаут потока (секунды) для UDP/ICMP (после бездействия поток закрывается)
FLOW_TIMEOUT = 10.0

# Структуры для потоков. Ключ – кортеж (ip1, port1, ip2, port2, proto).
# Значение – словарь со статистиками.
flows = {}
flows_lock = threading.Lock()

conn_cache = {}
conn_cache_lock = threading.Lock()
CACHE_INTERVAL = 0.2  # секунд

def refresh_conn_cache():
    """
    Фоновая функция: каждые CACHE_INTERVAL секунд читает psutil.net_connections
    и заполняет conn_cache. Ключ формируется в том же формате, что и get_flow_key().
    """
    while True:
        new_cache = {}
        for conn in psutil.net_connections(kind='inet'):
            if not conn.laddr or not conn.raddr:
                continue
            l_ip, l_port = conn.laddr
            r_ip, r_port = conn.raddr
            proto = conn.family  # AF_INET / AF_INET6, но ниже мы требуем tcp/udp/icmp
            # psutil не даёт прямо номер протокола (6 или 17),
            # но можно определить по типу сокета:
            #   если conn.type == SOCK_STREAM → proto=6; если SOCK_DGRAM → proto=17
            from socket import SOCK_STREAM, SOCK_DGRAM
            if conn.type == SOCK_STREAM:
                pnum = 6
            elif conn.type == SOCK_DGRAM:
                pnum = 17
            else:
                continue

            # Записываем оба направления
            key1 = (l_ip, l_port, r_ip, r_port, pnum)
            key2 = (r_ip, r_port, l_ip, l_port, pnum)
            new_cache[key1] = conn.pid
            new_cache[key2] = conn.pid

        with conn_cache_lock:
            conn_cache.clear()
            conn_cache.update(new_cache)

        time.sleep(CACHE_INTERVAL)

threading.Thread(target=refresh_conn_cache, daemon=True).start()

def get_flow_key(pkt):
    """
    Формирует ключ потока по IP/портам/протоколу.
    Поток двунаправленный: гарантируем, что (src, sport) <= (dst, dport) по порядку.
    """
    ip = pkt[IP]
    proto = ip.proto
    if proto == 1 and ICMP in pkt:
        src = ip.src; dst = ip.dst; sport = pkt[ICMP].type; dport = 0
    elif proto == 6 and TCP in pkt:
        src = ip.src; dst = ip.dst; sport = pkt[TCP].sport; dport = pkt[TCP].dport
    elif proto == 17 and UDP in pkt:
        src = ip.src; dst = ip.dst; sport = pkt[UDP].sport; dport = pkt[UDP].dport
    else:
        return None
    if (src, sport) <= (dst, dport):
        return (src, sport, dst, dport, proto), True
    else:
        return (dst, dport, src, sport, proto), False

def update_flow(pkt):
    """
    Обрабатывает один пакет: обновляет статистику потока и,
    если это FIN/RST TCP, сразу «попробовать» завершить поток.
    """
    res = get_flow_key(pkt)

    # if IP in pkt:
    #     src_ip = pkt[IP].src
    #     dst_ip = pkt[IP].dst
    #     if ipaddress.ip_address(src_ip).is_private and ipaddress.ip_address(dst_ip).is_private:
    #         return

    if res is None:
        return
    key, is_forward = res
    t = pkt.time

    flow_to_finalize = None

    with flows_lock:
        flow = flows.get(key)
        if flow is None:

            # if TCP in pkt and (pkt[TCP].flags & 0x01):
            #     return

            pid = get_process_for_flow(key)

            flow = {
                "pid": pid,
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
                # для финализации:
                "dst_port": key[3]
            }
            flows[key] = flow

        flow["last_time"] = t
        direction = "fwd" if is_forward else "bwd"
        length = len(pkt)

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

        ip_hdr_len = pkt[IP].ihl * 4
        if TCP in pkt:
            tcp_hdr_len = pkt[TCP].dataofs * 4
            hdr_len = ip_hdr_len + tcp_hdr_len
            win = pkt[TCP].window
            if direction == "fwd" and flow["fwd_init_win"] is None:
                flow["fwd_init_win"] = win
            if direction == "bwd" and flow["bwd_init_win"] is None:
                flow["bwd_init_win"] = win
            payload_len = length - hdr_len
            if direction == "fwd" and payload_len > 0:
                flow["fwd_act_data_pkts"] += 1
                if flow["fwd_min_seg_size"] is None or payload_len < flow["fwd_min_seg_size"]:
                    flow["fwd_min_seg_size"] = payload_len
        elif UDP in pkt:
            udp_hdr_len = 8
            hdr_len = ip_hdr_len + udp_hdr_len
        elif ICMP in pkt:
            icmp_hdr_len = 8
            hdr_len = ip_hdr_len + icmp_hdr_len
        else:
            hdr_len = ip_hdr_len

        if direction == "fwd":
            flow["fwd_hdr_lens"].append(hdr_len)
        else:
            flow["bwd_hdr_lens"].append(hdr_len)

        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x01:  # FIN
                flow["fin_count"] += 1
                flow["fin_count"] = min(flow["fin_count"], 1)
                # Удаляем поток прямо здесь из словаря под локом:
                flow_to_finalize = flows.pop(key, None)
            if flags & 0x10:  # ACK
                flow["ack_count"] += 1
                flow["ack_count"] = min(flow["ack_count"], 1)
            if flags & 0x08:  # PSH
                if direction == "fwd":
                    flow["fwd_psh"] += 1
                    flow["fwd_psh"] = min(flow["fwd_psh"], 1)
                else:
                    flow["bwd_psh"] += 1
                    flow["bwd_psh"] = min(flow["bwd_psh"], 1)

    # Если поток помечен на финализацию, вызывем compute+predict вне локa
    if flow_to_finalize is not None:
        process_and_finalize(key, flow_to_finalize)

def compute_features(flow):
    """
    Вычисляет все 52 признака для потока из накопленных статистик.
    """
    duration = flow["last_time"] - flow["start_time"]
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

    feature_flow_bytes_s = total_bytes / duration if duration > 0 else 0.0
    feature_flow_pkts_s = total_pkts / duration if duration > 0 else 0.0

    iat_min, iat_max = min_max(iats)
    iat_mean, iat_std = mean_std(iats)

    fwd_iat_total = sum(fwd_iats) if fwd_iats else 0.0
    fwd_iat_min, fwd_iat_max = min_max(fwd_iats)
    fwd_iat_mean, fwd_iat_std = mean_std(fwd_iats)

    bwd_iat_total = sum(bwd_iats) if bwd_iats else 0.0
    bwd_iat_min, bwd_iat_max = min_max(bwd_iats)
    bwd_iat_mean, bwd_iat_std = mean_std(bwd_iats)

    # ИСПРАВЛЕНИЕ: Используем сумму длин заголовков, а не максимум
    fwd_hdr_total = sum(fwd_hdrs) if fwd_hdrs else 0
    bwd_hdr_total = sum(bwd_hdrs) if bwd_hdrs else 0

    feature_fwd_pkts_s = fwd_pkts / duration if duration > 0 else 0.0
    feature_bwd_pkts_s = bwd_pkts / duration if duration > 0 else 0.0

    all_min, all_max = min_max(all_sizes)
    all_mean, all_std = mean_std(all_sizes)
    all_var = all_std ** 2

    fin_count = flow["fin_count"]
    psh_count = flow["fwd_psh"] + flow["bwd_psh"]
    ack_count = flow["ack_count"]

    avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0.0

    subflow_fwd_bytes = fwd_bytes # Это известное дублирование признака в CICIDS-2017

    init_win_fwd = flow["fwd_init_win"] or 0
    init_win_bwd = flow["bwd_init_win"] or 0

    act_data_pkt_fwd = flow["fwd_act_data_pkts"]

    min_seg_size_forward = flow["fwd_min_seg_size"] or 0

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
    """
    Обрабатывает ранее выбранный поток: вычисляет признаки, запускает модель и выводит результат.
    """
    features = compute_features(flow)

    if key[0] == '103.29.183.65' or key[2] == '103.29.183.65':
        print(','.join(list(map(str, features))))


    x = np.array(features, dtype=np.float32).reshape(1, -1)
    x_scaled = scaler.transform(x)

    probs = xgb_clf.predict_proba(x_scaled)

    # pid = get_process_for_flow(key)
    # proc_name = psutil.Process(pid).name() if pid else "Unknown"

    pid = flow["pid"]
    if not pid:
        pid = get_process_for_flow(key)

    if pid:
        try:
            proc_name = psutil.Process(pid).name()
        except psutil.NoSuchProcess:
            proc_name = "Unknown"
    else:
        proc_name = "Unknown"

    # label from XGBoost
    label = CLASS_LIST[np.argmax(probs)]
    score = probs.max()
    safe_score = probs[0][0]

    # Try hybrid detector for richer status if available
    detector = get_detector(models_dir=".")
    status = ""
    threat_prob = ""
    anomaly_consensus = ""
    if detector is not None:
        try:
            det = detector.instance_analyze_flow(features)
            status = det.get("status", "")
            threat_prob = f"{det.get('threat_prob', 0):.6f}"
            anomaly_consensus = f"{det.get('anomaly_consensus', 0):.6f}"
        except Exception:
            status = ""

    print(f"[{time.strftime('%H:%M:%S')}] Поток {key}: процесс={proc_name}, score={score:.3f}, метка={label}, status={status}")

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts},{pid or ''},{proc_name},{safe_score:.6f},{label},{status},{threat_prob},{anomaly_consensus}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)

def get_process_for_flow(key):
    """
    Пытается найти PID процесса, соответствующего потоку.
    """
    # src_ip, src_port, dst_ip, dst_port, proto = key
    # current_connections = psutil.net_connections(kind='inet')
    # for conn in current_connections:
    #     if not conn.laddr or not conn.raddr:
    #         continue
    #     l_ip, l_port = conn.laddr
    #     r_ip, r_port = conn.raddr
    #     if (l_ip == src_ip and l_port == src_port and r_ip == dst_ip and r_port == dst_port) or \
    #             (l_ip == dst_ip and l_port == dst_port and r_ip == src_ip and r_port == src_port):
    #         return conn.pid
    #
    # return None

    with conn_cache_lock:
        return conn_cache.get(key)

def timeout_watcher():
    """
    Фоновая функция: периодически проверяет потоки на таймаут и завершает «застрявшие».
    """
    while True:
        now = time.time()
        timed_out = []
        with flows_lock:
            for key, flow in list(flows.items()):
                if now - flow["last_time"] > FLOW_TIMEOUT:
                    timed_out.append((key, flows.pop(key)))

        # Обрабатываем завершённые потоки вне локa
        for key, flow in timed_out:
            # print(f"[{time.strftime('%H:%M:%S')}] Поток {key} закрыт по таймауту")
            process_and_finalize(key, flow)
        time.sleep(1.0)

# Запуск потока-«смотрителя» таймаута
threading.Thread(target=timeout_watcher, daemon=True).start()

def packet_callback(pkt):
    """
    Основной callback: при получении пакета обновляем поток.
    """
    if IP in pkt and (TCP in pkt or UDP in pkt or ICMP in pkt):
        # print(pkt.summary())
        update_flow(pkt)

# Запуск снифера (необходимо с правами администратора)
print("Запуск перехвата трафика...")
sniff(prn=packet_callback, store=False)
