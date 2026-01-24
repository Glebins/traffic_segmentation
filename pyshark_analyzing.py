import pyshark
from datetime import datetime


def print_http_packet(pkt):
    print('\n' + '-' * 80)
    capture_time = pkt.sniff_time
    print(f"[Время захвата пакета, с:мкс] {capture_time.second}:{capture_time.microsecond}")
    start_time = datetime.now()
    print(f"[Время начала обработки пакета, с:мкс] {start_time.second}:{start_time.microsecond}\n")

    # ---- Layer-2 (Ethernet) ----
    eth = pkt.eth
    print(f"[Layer 2] {eth.src}  ➜  {eth.dst}")

    # ---- Layer-3 (IP) ----
    ip_layer = pkt.ip if hasattr(pkt, 'ip') else pkt.ipv6
    print(f"[Layer 3] {ip_layer.src} ➜ {ip_layer.dst}")

    # ---- Layer-4 (TCP) ----
    tcp = pkt.tcp
    print(f"[Layer 4] {tcp.srcport} ➜ {tcp.dstport}  Seq={tcp.seq} Ack={tcp.ack}")

    # ---- Layer-7 (HTTP) ----
    if hasattr(pkt, 'http'):
        http = pkt.http
        if hasattr(http, 'request_method'):
            host = getattr(http, 'host', '')
            uri = getattr(http, 'request_uri', '')
            print(f"[Layer 7] HTTP REQUEST  {http.request_method} http://{host}{uri}")
        elif hasattr(http, 'response_code'):
            print(f"[Layer 7] HTTP RESPONSE {http.response_code} {http.response_phrase}")

    # print(f"[Info] Packet size: {pkt.length} bytes")
    end_time = datetime.now()
    print(f"\n[Время окончания обработки пакета, с:мкс] {end_time.second}:{end_time.microsecond}")

    time_capture_to_end = round((end_time - capture_time).total_seconds() * 1000, 2)
    print(f"[Время, затраченное на парсинг пакета с момента его захвата, мс] {time_capture_to_end}")

    time_start_to_end = round((end_time - start_time).total_seconds() * 1000, 2)
    print(f"[Время чистого разбора пакета (работы функции), мс] {time_start_to_end}")


if __name__ == "__main__":
    capture = pyshark.LiveCapture(interface='Беспроводная сеть',
                                  display_filter='http')
    print("[*] Capturing HTTP packets...\nPyShark")
    try:
        for packet in capture.sniff_continuously():
            print_http_packet(packet)
    except KeyboardInterrupt:
        print("\n[*] Stopping capture — goodbye!")
