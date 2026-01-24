import time
import win32pipe, win32file, pywintypes
import codecs
import subprocess
import os
from datetime import datetime, timezone
import ipaddress
import psutil

def load_local_addresses():
    """Возвращает set строк адресов (без %scope) для всех интерфейсов хоста."""
    addrs = set()
    for iface, lst in psutil.net_if_addrs().items():
        for a in lst:
            addr = getattr(a, 'address', None)
            if not addr:
                continue
            # Снять scope (например fe80::1%eth0) — keep only address part
            if '%' in addr:
                addr = addr.split('%', 1)[0]
            try:
                # нормализуем (например ::ffff:192.168.0.1 → IPv6 mapped; оставляем строк)
                ip = ipaddress.ip_address(addr)
                addrs.add(ip.exploded if ip.version == 6 else ip.compressed)
            except Exception:
                continue
    return addrs

LOCAL_ADDRS = load_local_addresses()

def classify_ip(ip_str):
    """Классифицирует ip: 'loopback','host','private','linklocal','public','unspecified'."""
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
    # is_global may be True also for routable addresses
    return 'public'

def decide_src_dst(local_ip, local_port, remote_ip, remote_port, direction):
    """
    Возвращает (src_ip, src_port, dst_ip, dst_port, reason) или None чтобы отбросить.
    direction — "OUT" или "IN" (как от ETW/C#).
    Логика:
      - если любой из адресов loopback → отброс
      - если neither IP is 'host' (т.е. пакеты не участвуют локальные интерфейсы) → отброс
      - если один из них host и другой не host:
            OUT  => src = host(local) ; dst = remote
            IN   => src = remote ; dst = host(local)
      - если оба host (редко, два адреса интерфейсов) — используем direction: 
            OUT => src = local, IN => src = remote (и оставляем оба)
      - если оба не-host но private/public combo (например два LAN адреса), 
        возвращаем None (можно изменить по политике).
    """
    # normalize remove %scope
    def norm(a): 
        return a.split('%',1)[0] if a else a

    l_ip = norm(local_ip)
    r_ip = norm(remote_ip)
    l_port = str(local_port or '')
    r_port = str(remote_port or '')

    cls_l = classify_ip(l_ip)
    cls_r = classify_ip(r_ip)

    # drop loopback or unspecified
    if cls_l == 'loopback' or cls_r == 'loopback' or cls_l == 'unspecified' or cls_r == 'unspecified':
        return None

    host_l = (cls_l == 'host')
    host_r = (cls_r == 'host')

    # If neither endpoint is our host — it's not our flow (drop)
    if not host_l and not host_r:
        # There is a corner case: ETW might surface non-local flows, but
        # in our design we track flows involving this host only.
        return None

    # If exactly one of endpoints is host
    if host_l ^ host_r:
        # determine which side is local host (should be local_ip normally)
        if direction == "OUT":
            # source is local host
            src_ip, src_port = (l_ip, l_port) if host_l else (r_ip, r_port)
            dst_ip, dst_port = (r_ip, r_port) if host_l else (l_ip, l_port)
        else:  # IN
            # source is remote, destination is local host
            src_ip, src_port = (r_ip, r_port) if host_l else (l_ip, l_port)
            dst_ip, dst_port = (l_ip, l_port) if host_l else (r_ip, r_port)
        return src_ip, src_port, dst_ip, dst_port, 'host-peer'

    # If both are host (both addresses belong to this machine's interfaces)
    if host_l and host_r:
        # Use direction: OUT means local_ip acted as sender, IN means remote_ip acted as sender
        if direction == "OUT":
            src_ip, src_port = l_ip, l_port
            dst_ip, dst_port = r_ip, r_port
        else:
            src_ip, src_port = r_ip, r_port
            dst_ip, dst_port = l_ip, l_port
        return src_ip, src_port, dst_ip, dst_port, 'host-host'

    # Both endpoints are not-host but one or both are private (LAN peers) — drop or mark
    # По умолчанию — drop (мы отслеживаем трафик, связанный с этой машиной).
    # Если нужно учитывать меж-устройственный LAN-трафик, можно вернуть 'lan-peer'
    return None

class NetworkPacket:
    def __init__(self, data):
        parts = data.split('|')
        if len(parts) != 11:
            raise ValueError("Bad packet line: " + data)
        self.id = parts[0]
        self.pid = parts[1]
        self.proc_name = parts[2]
        self.proto = parts[3]
        self.direction = parts[4]
        self.src_ip = parts[5]
        self.src_port = parts[6]
        self.dst_ip = parts[7]
        self.dst_port = parts[8]
        self.size = int(parts[9])
        self.ts_micros = int(parts[10])
        self.reason_direction = None

        # packed_vals = decide_src_dst(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.direction)
        # if packed_vals == None:
        #     self.reason_direction = None
        # else:
        #     self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.reason_direction = packed_vals

    def ts_dt(self):
        return datetime.fromtimestamp(self.ts_micros / 1_000_000)

    def __str__(self):
        t = self.ts_dt().strftime("%H:%M:%S.%f")[:-3]
        return (f"{self.id}. [{self.direction}] {self.proc_name} ({self.pid}) "
                f"{self.proto} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}\t{self.size}B\t{t}\t{self.reason_direction}")

def start_capture_engine():
    engine_path = "./publish/EtwTcp.exe"
    subprocess.Popen([engine_path], creationflags=subprocess.CREATE_NEW_CONSOLE)

    pipe_name = r'\\.\pipe\NetMonitorPipe'
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

    print("Соединение с ядром установлено. Чтение пакетов...")

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
                            packet = NetworkPacket(line)
                        except Exception as e:
                            # пропускаем битые строки
                            print("Bad line:", line, "err:", e)
                            continue
                        yield packet
        except Exception as e:
            print(f"The connection aborted: {e}")
            break
        except KeyboardInterrupt:
            print("The end")
            break

if __name__ == "__main__":
    # Пример использования в вашем коде:
    i = 1
    for pkt in start_capture_engine():
        print(pkt)
        i += 1
        
        # Здесь вы можете вызывать свои функции из НИР:
        # update_flow_stats(pkt)
        # model.predict(...)