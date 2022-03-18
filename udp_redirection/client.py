import socket
import time
from datetime import datetime


def send():
    sent_count = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        print('UDP Client send to server1...')
        while True:
            s.sendto(f'sent={sent_count} Hello, server1'.encode('utf-8'), ('10.0.0.1', 11111))
            sent_count += 1
            now = datetime.now().strftime("%H:%M:%S")
            print(f"[{now}] {s.recv(1024).decode('utf-8')}")
            time.sleep(1)


if __name__ == '__main__':
    send()
