import socket
import threading
import sys

BUFFER_SIZE = 1024  # Maximum number of bytes per received message

# Function to receive and print messages from the server
def receive_messages(sock):
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            print(data.decode())
        except:
            break

# Function to start the client and handle message sending
def start_client(server_ip, client_ip, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.bind((client_ip, 0))  # Bind to any available port
    server_address = (server_ip, port)

    # Send GREETING
    client_socket.sendto(b"GREETING", server_address)

    # Start thread to receive messages
    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    print(f"Hi! This is {client_ip}\nType your message and press Enter:")

    while True:
        try:
            message = input()
            if message:
                full_message = f"MESSAGE: {message}"
                client_socket.sendto(full_message.encode(), server_address)
        except KeyboardInterrupt:
            print("\nClient exiting.")
            break

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python ChatClient.py <server-ip> <client-ip> <port>")
        sys.exit(1)

    server_ip = sys.argv[1]
    client_ip = sys.argv[2]
    port = int(sys.argv[3])

    start_client(server_ip, client_ip, port)
