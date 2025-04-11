import socket
import sys
from datetime import datetime

PORT = 9090
BUFFER_SIZE = 1024
clients = set()

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def start_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ip, int(port)))
    print(f"[{now()}] Server Initialized on port {port}...")

    while True:
        data, addr = server_socket.recvfrom(BUFFER_SIZE)
        message = data.decode()

        if message == "GREETING":
            clients.add(addr)
            print(f"[{now()}] Greeting received from {addr}")
        elif message.startswith("MESSAGE:"):
            msg_content = message[len("MESSAGE:"):].strip()
            print(f"[{now()}] Message from {addr}: {msg_content}")
            forward = f"<From {addr[0]}:{addr[1]}>: {msg_content}"
            for client in clients:
                server_socket.sendto(forward.encode(), client)
        else:
            pass

if __name__ == "__main__":
    server_ip = sys.argv[1]
    server_port = sys.argv[2]
    start_server(server_ip, server_port)
