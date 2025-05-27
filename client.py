# ChatClient.py
import hashlib
import os
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

def hash_pw(pw, salt=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100_000, dklen=32)
    return salt, dk

def receive_loop(sock):
    while True:
        try:
            data, _ = sock.recvfrom(BUFFER_SIZE)
            msg   = deserialize(data)
            mtype = msg.get("type")
            body  = msg.get("body", "")
            time  = msg.get("time")
            username = msg.get("username")
            frm = msg.get("from")

            if mtype == "GREETING_ACK":
                print(f"\n[{frm}]> {mtype} :👋 Greeting acknowledged, {body}")
                print("You can now send messages. Type and press Enter (Ctrl+C to exit).")
            elif mtype == "MESSAGE":
                print(f"<{username}><{time}> {body}")
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
        sign_flag = int(input("\nDo you want to [1] Sign Up or [2] Sign In? "))
        if sign_flag == 1:
            # your existing signup flow (client-side hashing)
            print("\nSIGNUP:<username>:<password>")
            text = input("SIGNUP:").split(":")
            username, password = text
            salt, dk = hash_pw(password.strip(), salt=None)
            msg = {
                "type": "SIGNUP",
                "body": {
                    "username": username.strip(),
                    "salt": salt,
                    "dh": dk
                }
            }
            print(msg)
            sock.sendto(serialize(msg), (server_ip, server_port))
            data, _ = sock.recvfrom(BUFFER_SIZE)
            resp = deserialize(data)
            if resp["type"] == "SIGNUP_OK":
                print(f"[Server:{resp['type']}] Sign-Up successful! Please sign in.")
            else:
                print(f"[Server:{resp['type']}] {resp.get('body',{})}")
            continue

        else:
            # ——— SIGNIN challenge–response ———
            username = input("Username: ").strip()
            password = getpass("Password: ").strip()

            # 1) ask server for our salt
            sock.sendto(serialize({
                "type": "SIGNIN_REQUEST",
                "body": {"username": username}
            }), (server_ip, server_port))

            # 2) receive salt (or fail)
            data, _ = sock.recvfrom(BUFFER_SIZE)
            resp = deserialize(data)
            if resp["type"] != "SIGNIN_SALT":
                print(f"[Server:{resp['type']}] {resp.get('body',{}).get('reason',"")}")
                continue

            salt = resp["body"]["salt"]
            # 3) derive the same key on the client
            _, dk = hash_pw(password, salt)

            # 4) send only the derived key
            sock.sendto(serialize({
                "type": "SIGNIN_HASH",
                "body": {
                    "username": username,
                    "hash": dk
                }
            }), (server_ip, server_port))

            # 5) wait for OK/FAIL
            data, _ = sock.recvfrom(BUFFER_SIZE)
            resp = deserialize(data)
            if resp["type"] == "SIGNIN_OK":
                threading.Thread(target=receive_loop, args=(sock,), daemon=True).start()
                print(f"\n[Server:{resp['type']}] Sign-In successful!")
                # send GREETING
                sock.sendto(serialize({"type":"GREETING"}), (server_ip, server_port))
                break
            else:
                print(f"[Server:{resp['type']}] {resp.get('body',{}).get('reason',"")}")
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
