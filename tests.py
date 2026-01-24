# #!/usr/bin/env python3
# # Windows-only. Запуск: с правами администратора.
# # Требует: scapy, psutil
# import ctypes, struct, socket, threading, time, psutil
# from ctypes import wintypes
# from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, ARP

# # ---- WinAPI helpers ----
# iphlpapi = ctypes.WinDLL('iphlpapi')
# DWORD = wintypes.DWORD
# PVOID = wintypes.LPVOID
# AF_INET = 2
# TCP_TABLE_OWNER_PID_ALL = 5
# UDP_TABLE_OWNER_PID = 1

# def _inet_ntoa_le(dw):
#     return socket.inet_ntoa(struct.pack('<I', dw))

# def _port_from_dword(dw):
#     # correct extraction: port is stored in network byte order in the low WORD on many Windows versions,
#     # try both common options (high WORD and low WORD) and choose reasonable port range.
#     p1 = socket.ntohs((dw >> 16) & 0xffff)
#     p2 = socket.ntohs(dw & 0xffff)
#     # choose value in valid port range (1..65535)
#     if 1 <= p2 <= 65535 and not (p2 >= 49152 and p2 <= 65535 and p1 < 1024):
#         return p2
#     return p1

# def _get_tcp_table_once():
#     GetExtendedTcpTable = iphlpapi.GetExtendedTcpTable
#     GetExtendedTcpTable.restype = DWORD
#     GetExtendedTcpTable.argtypes = [PVOID, ctypes.POINTER(DWORD), wintypes.BOOL, DWORD, DWORD, DWORD]
#     size = DWORD(0)
#     res = GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
#     if res not in (0, 122):
#         return []
#     buf = ctypes.create_string_buffer(size.value)
#     res = GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
#     if res != 0:
#         return []
#     num = struct.unpack_from("<I", buf, 0)[0]
#     rows=[]
#     offset = 4
#     row_size = 24
#     for i in range(num):
#         base = offset + i * row_size
#         try:
#             dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid = struct.unpack_from("<6I", buf, base)
#         except struct.error:
#             continue
#         try:
#             l_ip = socket.inet_ntoa(struct.pack('!I', dwLocalAddr))
#         except Exception:
#             l_ip = _inet_ntoa_le(dwLocalAddr)
#         try:
#             r_ip = socket.inet_ntoa(struct.pack('!I', dwRemoteAddr))
#         except Exception:
#             r_ip = _inet_ntoa_le(dwRemoteAddr)
#         l_port = _port_from_dword(dwLocalPort)
#         r_port = _port_from_dword(dwRemotePort)
#         rows.append((l_ip, l_port, r_ip, r_port, int(dwOwningPid)))
#     return rows

# def _get_udp_table_once():
#     GetExtendedUdpTable = iphlpapi.GetExtendedUdpTable
#     GetExtendedUdpTable.restype = DWORD
#     GetExtendedUdpTable.argtypes = [PVOID, ctypes.POINTER(DWORD), wintypes.BOOL, DWORD, DWORD, DWORD]
#     size = DWORD(0)
#     res = GetExtendedUdpTable(None, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
#     if res not in (0, 122):
#         return []
#     buf = ctypes.create_string_buffer(size.value)
#     res = GetExtendedUdpTable(buf, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
#     if res != 0:
#         return []
#     num = struct.unpack_from("<I", buf, 0)[0]
#     rows=[]
#     offset = 4
#     row_size = 12
#     for i in range(num):
#         base = offset + i * row_size
#         try:
#             dwLocalAddr, dwLocalPort, dwOwningPid = struct.unpack_from("<3I", buf, base)
#         except struct.error:
#             continue
#         try:
#             l_ip = socket.inet_ntoa(struct.pack('!I', dwLocalAddr))
#         except Exception:
#             l_ip = _inet_ntoa_le(dwLocalAddr)
#         l_port = _port_from_dword(dwLocalPort)
#         rows.append((l_ip, l_port, None, None, int(dwOwningPid)))
#     return rows

# # ---- caches and refresh thread ----
# conn_cache = {}
# conn_cache_lock = threading.Lock()
# CACHE_INTERVAL = 0.2

# def refresh_conn_cache():
#     while True:
#         new_cache = {}
#         try:
#             tcp_rows = _get_tcp_table_once()
#             for l_ip,l_port,r_ip,r_port,pid in tcp_rows:
#                 key1=(l_ip,l_port,r_ip,r_port,6); key2=(r_ip,r_port,l_ip,l_port,6)
#                 new_cache[key1]=pid; new_cache[key2]=pid
#             udp_rows = _get_udp_table_once()
#             for l_ip,l_port,_,_,pid in udp_rows:
#                 new_cache[(l_ip,l_port,None,None,17)]=pid
#                 new_cache[(l_ip,l_port,'*','*',17)]=pid
#         except Exception:
#             pass
#         with conn_cache_lock:
#             conn_cache.clear(); conn_cache.update(new_cache)
#         time.sleep(CACHE_INTERVAL)

# # ---- fallback psutil scan (synchronous) ----
# def psutil_lookup(src, sport, dst, dport, proto):
#     try:
#         for c in psutil.net_connections(kind='inet'):
#             if not c.laddr: continue
#             try:
#                 l_ip, l_port = c.laddr
#             except Exception:
#                 continue
#             r = getattr(c, 'raddr', None)
#             if r:
#                 try:
#                     r_ip, r_port = r
#                 except Exception:
#                     r_ip=None; r_port=None
#             else:
#                 r_ip=None; r_port=None
#             pnum = None
#             if c.type == socket.SOCK_STREAM: pnum=6
#             elif c.type == socket.SOCK_DGRAM: pnum=17
#             else: continue
#             if pnum != proto: continue
#             # exact
#             if l_ip==src and l_port==sport and r_ip==dst and r_port==dport: return c.pid
#             if l_ip==dst and l_port==dport and r_ip==src and r_port==sport: return c.pid
#             # partial local
#             if l_ip==src and l_port==sport: return c.pid
#             if r_ip==src and r_port==sport: return c.pid
#     except Exception:
#         pass
#     return None

# # ---- matching logic with sync refresh and fallback ----
# def find_pid_for_packet(src, sport, dst, dport, proto):
#     # try cached fast
#     with conn_cache_lock:
#         if proto in (6,17):
#             k=(src,sport,dst,dport,proto)
#             pid=conn_cache.get(k)
#             if pid: return pid
#             rev=(dst,dport,src,sport,proto)
#             pid=conn_cache.get(rev)
#             if pid: return pid
#             if proto==17:
#                 pid=conn_cache.get((src,sport,None,None,17))
#                 if pid: return pid
#                 pid=conn_cache.get((src,sport,'*','*',17))
#                 if pid: return pid
#             # partial scan in cache
#             for (k_src,k_sp,k_dst,k_dp,k_proto), v in conn_cache.items():
#                 if k_proto!=proto: continue
#                 if k_src==src and k_sp==sport: return v
#                 if k_dst==src and k_dp==sport: return v
#     # not found -> synchronous immediate refresh of WinAPI cache and retry
#     try:
#         new = {}
#         tcp_rows = _get_tcp_table_once()
#         for l_ip,l_port,r_ip,r_port,pid in tcp_rows:
#             new[(l_ip,l_port,r_ip,r_port,6)]=pid
#             new[(r_ip,r_port,l_ip,l_port,6)]=pid
#         udp_rows = _get_udp_table_once()
#         for l_ip,l_port,_,_,pid in udp_rows:
#             new[(l_ip,l_port,None,None,17)]=pid
#             new[(l_ip,l_port,'*','*',17)]=pid
#     except Exception:
#         new={}
#     # try new snapshot
#     if proto in (6,17):
#         if (src,sport,dst,dport,proto) in new: return new[(src,sport,dst,dport,proto)]
#         if (dst,dport,src,sport,proto) in new: return new[(dst,dport,src,sport,proto)]
#         if proto==17 and (src,sport,None,None,17) in new: return new[(src,sport,None,None,17)]
#         for (k_src,k_sp,k_dst,k_dp,k_proto), v in new.items():
#             if k_proto!=proto: continue
#             if k_src==src and k_sp==sport: return v
#             if k_dst==src and k_dp==sport: return v
#     # fallback psutil full scan
#     pid = psutil_lookup(src,sport,dst,dport,proto)
#     if pid: return pid
#     return None

# # ---- packet parsing and callback ----
# def identify_packet_type(pkt):
#     if pkt.haslayer(ARP): return "arp",None,None,0,0
#     if pkt.haslayer(TCP):
#         ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
#         return "tcp", ip.src, ip.dst, int(pkt[TCP].sport), int(pkt[TCP].dport)
#     if pkt.haslayer(UDP):
#         ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
#         s = int(getattr(pkt[UDP],'sport',0)); d = int(getattr(pkt[UDP],'dport',0))
#         if pkt.haslayer(DNS) or s==53 or d==53: return "dns",ip.src,ip.dst,s,d
#         return "udp",ip.src,ip.dst,s,d
#     if pkt.haslayer(ICMP):
#         ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
#         return "icmp",ip.src,ip.dst,0,0
#     if pkt.haslayer(IP) or pkt.haslayer(IPv6):
#         ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
#         return "ip",ip.src,ip.dst,0,0
#     return "other",None,None,0,0

# unknown_counter = 0
# def packet_callback(pkt):
#     global unknown_counter
#     pkt_type, src, dst, sport, dport = identify_packet_type(pkt)
#     pid=None; proc="Unknown"
#     if src and dst is not None:
#         proto_num = 0
#         if pkt_type=="tcp": proto_num=6
#         elif pkt_type in ("udp","dns"): proto_num=17
#         elif pkt_type=="icmp": proto_num=1
#         if proto_num!=0:
#             pid = find_pid_for_packet(src,sport,dst,dport,proto_num)
#     if pid:
#         try:
#             proc = psutil.Process(pid).name()
#         except Exception:
#             proc = f"pid:{pid}"
#     else:
#         unknown_counter += 1
#         # debug only when unknown (print limited info)
#         with conn_cache_lock:
#             sample_keys = list(conn_cache.keys())[:6]
#             cache_len = len(conn_cache)
#         print(f"[NO_PID#{unknown_counter}] cache_len={cache_len} sample_keys={sample_keys}")
#     print(f"{proc} {pkt_type} {src or '-'} {dst or '-'} {sport or '-'} {dport or '-'}")

# # ---- main ----
# if __name__ == "__main__":
#     t = threading.Thread(target=refresh_conn_cache, daemon=True); t.start()
#     print("[*] Сниффер запущен (Windows). Запускать от администратора. Ctrl+C для остановки.")
#     try:
#         sniff(prn=packet_callback, store=False)
#     except KeyboardInterrupt:
#         print("\n[*] Остановлено.")




# import pandas as pd

# CSV_PATH = "balanced.csv"

# def analyze_value_counts(csv_path):
#     df = pd.read_csv(csv_path).iloc[:, [10, 11, 12, 13, 16, 17, 20, 21, 22, 23, 24, 26, 40, 41, 50, 59, 60]]

#     print(f"Loaded {len(df)} rows, {len(df.columns)} columns\n")

#     for i, col in enumerate(df.columns):
#         print("=" * 80)
#         print(f"Column: {col}, {i}")
#         print("-" * 80)
#         vc = df[col].value_counts(dropna=False)
#         print(vc.head(10))   # показываем топ-20 значений
#         print("AVG: ", df[col].mean())
#         print(f"\nUnique values: {vc.shape[0]}")
#         print()
#         if i == 1:
#             print(df[df[col] > 10000000].index)

# if __name__ == "__main__":
#     analyze_value_counts(CSV_PATH)




import pandas as pd
CSV_PATH = "test_mal.csv"
last_row = pd.read_csv(CSV_PATH).iloc[-2, [10, 11, 12, 13, 16, 17, 20, 21, 22, 23, 24, 26, 40, 41, 50, 59, 60]]
print(last_row.tolist())



# import pandas as pd
# CSV_PATH = "flow_features.csv"
# df = pd.read_csv(CSV_PATH)
# selected_features = [10, 11, 12, 13, 16, 17, 20, 21, 22, 23, 24, 26, 40, 41, 50, 59, 60]
# max_samples = 150

# col_names = df.columns.values[selected_features]
# df_cleaned = df.drop_duplicates(subset=col_names)
# balanced_df = df_cleaned.groupby('proc_name', group_keys=False).apply(lambda x: x.sample(n=min(len(x), max_samples), random_state=42))
# balanced_df.to_csv('balanced.csv', index=False)

# print(f'Было строк: {len(df)}')
# print(f'Now: {len(balanced_df)}')
# print(f'Unique processes: {balanced_df["proc_name"].nunique()}')
