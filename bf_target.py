# bf_target.py
# Простой TCP-сервер для тестов Brute-Force.
# Запуск: python bf_target.py
# Работает только на localhost по умолчанию.

import socket
import threading

HOST = "127.0.0.1"   # Используй localhost для безопасности
PORT = 21

# Ответ, который сервер будет посылать на каждый запрос (bytes)
RESPONSE_SIZE = 34    # подменяй под нужный тест (пример 34, 976)
RESPONSE_PAYLOAD = b"A" * RESPONSE_SIZE

def handle_client(conn, addr):
    try:
        # читаем запрос (не ждем слишком много - максимум 8KB)
        data = conn.recv(8192)
        # здесь можно симулировать обработку (временная задержка)
        # time.sleep(0.01)
        # отправляем ответ фиксированного размера
        conn.sendall(RESPONSE_PAYLOAD)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except:
            pass

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(200)
    print(f"Test server listening on {HOST}:{PORT}, response_size={RESPONSE_SIZE}")
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("shutting down")
    finally:
        s.close()

if __name__ == "__main__":
    main()
