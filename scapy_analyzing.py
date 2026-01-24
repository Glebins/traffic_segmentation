from scapy.all import sniff, Ether, IP, IPv6, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
# from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
from datetime import datetime


def print_packet(pkt):
    if not pkt.haslayer(TCP):
        return

    if not (pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse)):
        # pkt.haslayer(TLS) or pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello)):
        return

    print("\n" + "-" * 80)
    capture_time = datetime.fromtimestamp(pkt.time)
    print(f"[Время захвата пакета, с:мкс] {capture_time.second}:{capture_time.microsecond}")
    start_time = datetime.now()
    print(f"[Время начала обработки пакета, с:мкс] {start_time.second}:{start_time.microsecond}\n")

    # ---- Layer-2 (Ethernet) ----
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        print(f"[Layer 2] Ethernet: {eth.src} ➜ {eth.dst}")

    # ---- Layer-3 (IP) ----
    if pkt.haslayer(IP):
        ip = pkt[IP]
        print(f"[Layer 3] IPv4: {ip.src} ➜ {ip.dst}")
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        print(f"[Layer 3] IPv6: {ip6.src} ➜ {ip6.dst}")

    # ---- Layer-4 (TCP) ----
    tcp = pkt[TCP]
    print(f"[Layer 4] TCP: {tcp.sport} ➜ {tcp.dport}")

    # ---- Layer-7 (HTTP) ----
    if pkt.haslayer(HTTPRequest):
        http = pkt[HTTPRequest]
        host = http.Host.decode(errors="ignore") if http.Host else ''
        path = http.Path.decode(errors="ignore") if http.Path else '/'
        print(f"[Layer 7] HTTP Request: {http.Method.decode()} http://{host}{path}")

    elif pkt.haslayer(HTTPResponse):
        http = pkt[HTTPResponse]
        code = http.Status_Code.decode(errors="ignore") if http.Status_Code else '?'
        reason = http.Reason_Phrase.decode(errors="ignore") if http.Reason_Phrase else ''
        print(f"[Layer 7] HTTP Response: {code} {reason}")

    # elif pkt.haslayer(TLS) or pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello):
    #     print("[Layer 7] HTTPS traffic (TLS handshake or encrypted payload)")

    # print(f"[Info] Packet size: {len(pkt)} bytes")
    end_time = datetime.now()
    print(f"\n[Время окончания обработки пакета, с:мкс] {end_time.second}:{end_time.microsecond}")

    time_capture_to_end = round((end_time - capture_time).total_seconds() * 1000, 2)
    print(f"[Время, затраченное на парсинг пакета с момента его захвата, мс] {time_capture_to_end}")

    time_start_to_end = round((end_time - start_time).total_seconds() * 1000, 2)
    print(f"[Время чистого разбора пакета (работы функции), мс] {time_start_to_end}")


if __name__ == "__main__":
    # print("[*] Capturing HTTP and HTTPS packets only... (Ctrl+C to stop)")
    print("[*] Capturing HTTP packets...\nScapy")
    try:
        sniff(filter="tcp", prn=print_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped.")
