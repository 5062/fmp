import socket
from datetime import datetime


def recv():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('10.0.0.2', 22222))
        print('Server2 bind UDP on 22222...')
        while True:
            data, addr = s.recvfrom(1024)
            now = datetime.now().strftime("%H:%M:%S")
            print(f"[{now}] from {addr[0]}: {data.decode('utf-8')}")
            s.sendto(b'Hello, %s! This is server2' % addr[0].encode('utf-8'), addr)


if __name__ == '__main__':
    recv()
