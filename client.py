import socket
import threading
import sys
import pickle
from getpass import getpass

BUFFER_SIZE = 4096

def serialize(msg):
    return pickle.dumps(msg)

def deserialize(blob):
    return pickle.loads(blob)

def receive_loop(sock):
    while True:
        try:
            data, _ = sock.recvfrom(BUFFER_SIZE)
            msg   = deserialize(data)
            mtype = msg.get("type")
            body  = msg.get("body", "")
            if mtype == "GREETING_ACK":
                frm = msg.get("from")
                print(f"\n[{frm}]> {mtype} :👋 Greeting acknowledged, {body}")
                print("You can now send messages. Type and press Enter (Ctrl+C to exit).")
            elif mtype == "MESSAGE":
                frm  = msg.get("from")
                print(f"<{frm}> {body}")
            elif mtype == "ERROR":
                print(f"[Server] Error: {body.get('reason')}")
            else:
                # covers SIGNUP_OK/FAIL and SIGNIN_OK/FAIL
                print(f"[Server:{mtype}] {body}")
                print(3162)
        except Exception:
            break

def start_client(server_ip, client_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((client_ip, 0))
    print(f"Local address: {sock.getsockname()} → Server: {server_ip}:{server_port}")

    # 1) Ask user to sign up or sign in
    while True:
        sign_flag = int(input("\nDo you want to [1] Sign Up or [2] Sign In?"))
        if sign_flag == 1:
            print("SIGNUP:<username>:<password>")
            text = input("SIGNUP:").split(":")
            username, password = text
            msg = {"type":"SIGNUP", "body":{"username":username.strip(),"password":password.strip()}}
        else:
            print("SIGNIN:<username>:<password>")
            text = input("SIGNIN:").split(":")
            username, password = text
            msg = {"type":"SIGNIN", "body":{"username":username,"password":password}}

        sock.sendto(serialize(msg), (server_ip, server_port))

        # wait for response
        data, _ = sock.recvfrom(BUFFER_SIZE)
        resp = deserialize(data)
        if resp["type"] == "SIGNUP_OK":
            print(f"\n{resp["type"]}: Sign-Up successful! Please sign in.")
            sign_flag = 1
            continue
        if resp["type"] == "SIGNUP_FAIL":
            print(f"{resp["type"]}: {resp["body"]["reason"]}")
            continue
        if resp["type"] == "SIGNIN_OK":
            threading.Thread(target=receive_loop, args=(sock,), daemon=True).start()
            print(f"\n{resp["type"]}: Sign-In successful!")
            # send GREETING
            sock.sendto(serialize({"type":"GREETING"}), (server_ip, server_port))
            break
        if resp["type"] == "SIGNIN_FAIL":
            print(f"{resp["type"]}: {resp['body']['reason']}")
            continue

    # 2) Chat loop
    while True:
        try:
            text = input()
            if not text:
                continue
            pkt = {"type":"MESSAGE", "body": text}
            sock.sendto(serialize(pkt), (server_ip, server_port))
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python ChatClient.py <server-ip> <client-ip> <port>")
        sys.exit(1)
    srv_ip   = sys.argv[1]
    cli_ip   = sys.argv[2]
    srv_port = int(sys.argv[3])
    start_client(srv_ip, cli_ip, srv_port)
