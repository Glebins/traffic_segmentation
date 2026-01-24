# syn_scan_scappy.py  — требует scapy, запуск от администратора
from scapy.all import IP, TCP, send
from random import randint
import time

target = "8.8.8.8"
ports = range(1, 1024)
interval = 0.005   # 5 ms между пакетами — подстраивай

print("Запуск SYN-scan (Scapy). Нужны права администратора.")
for port in ports:
    sport = randint(1025, 65535)
    pkt = IP(dst=target)/TCP(sport=sport, dport=port, flags="S")
    send(pkt, verbose=False)
    time.sleep(interval)
