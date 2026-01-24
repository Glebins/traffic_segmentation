# simulate_bruteforce.py
# Запуск: python simulate_bruteforce.py --case 1
# Требует, чтобы bf_target.py был запущен (по умолчанию localhost:2222)

import socket
import time
from random import randint

TARGET = "127.0.0.1"
PORT = 21

def one_attempt(target, port, payload_bytes, recv_bytes, timeout=0.2):
    """Одна попытка: открываем TCP, отправляем payload_bytes, читаем ответ до recv_bytes, закрываем."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        if payload_bytes:
            s.sendall(payload_bytes)
        # пытаемся прочитать ответ (если есть) — это создаёт 'backward' пакет(и)
        try:
            data = s.recv(recv_bytes)
        except socket.timeout:
            data = b""
        s.close()
        return len(payload_bytes), len(data)
    except Exception as e:
        # при ошибке считаем, что ничего не отправлено/не получено
        return 0, 0

def simulate_case(target, port, attempts, payload_size, response_read_size, duration_sec):
    """
    Генерируем attempts подключений в общем окне duration_sec.
    Для случайности подмешиваем небольшую джиттер-задержку.
    """
    # Формируем одинаковый 'payload' (имитация поля логина):
    payload = (b"user=admin&pass=" + (b"X" * max(1, payload_size-16)))[:payload_size]

    # Расчёт интервала между попытками (в секундах)
    if attempts <= 1:
        interval = 0.0
    else:
        interval = max(0.0, duration_sec / attempts)

    print(f"Simulating: target={target}:{port}, attempts={attempts}, payload={payload_size}B, "
          f"server_resp_expect={response_read_size}B, duration~{duration_sec:.2f}s, interval~{interval:.3f}s")

    stats = {"sent_bytes":0, "recv_bytes":0, "sent_pkts":0, "recv_pkts":0}
    start = time.time()
    for i in range(attempts):
        # небольшая случайная вариация времени, чтобы IAT не идеальный
        jitter = (randint(-25,25) / 1000.0) * min(interval, 0.5)
        t0 = time.time()
        sb, rb = one_attempt(target, port, payload, response_read_size, timeout=1.0)
        stats["sent_bytes"] += sb
        stats["recv_bytes"] += rb
        if sb>0:
            stats["sent_pkts"] += 1
        if rb>0:
            stats["recv_pkts"] += 1
        # sleep remaining time to approximate overall duration
        elapsed = time.time() - t0
        to_sleep = max(0.0, interval + jitter - elapsed)
        time.sleep(to_sleep)
    total_time = time.time() - start
    print("Done. total_time=%.3fs, sent_pkts=%d, recv_pkts=%d, sent_bytes=%d, recv_bytes=%d" %
          (total_time, stats["sent_pkts"], stats["recv_pkts"], stats["sent_bytes"], stats["recv_bytes"]))
    return stats

# --- Presets, подобраны под твои два эталона ---
def case1():
    # Соответствует первой записи:
    # Duration ~ 8.8s, total forward packets ~9, fwd payload ~18B, server answers ~34B
    return simulate_case(TARGET, PORT,
                         attempts=9,
                         payload_size=18,
                         response_read_size=34,
                         duration_sec=8.8)

def case2():
    # Соответствует второй записи:
    # Duration ~13s, attempts ~21, payload ~640B, server answers ~976B
    return simulate_case(TARGET, PORT,
                         attempts=21,
                         payload_size=640,
                         response_read_size=976,
                         duration_sec=13.0)

if __name__ == "__main__":
    case_num = 1
    if case_num == 1:
        case1()
    else:
        case2()
