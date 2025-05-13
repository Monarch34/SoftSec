# ChatServer.py
import socket
import sys
import os
import hashlib
import hmac
import pickle
from datetime import datetime

# Server configuration
PORT = 9090
BUF_SZ = 4096

# In-memory stores
users = {}     # username → (salt: bytes, hash: bytes)
sessions = {}  # "ip:port" → {"username":…}


def now(typef: str):
    if typef == "server":
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    else:
        return datetime.now().strftime("%H:%M:%S")

def serialize(msg):
    return pickle.dumps(msg)

def deserialize(blob):
    return pickle.loads(blob)

def hash_pw(pw, salt=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100_000, dklen=32)
    return salt, dk

def addr_key(addr):
    return f"{addr[0]}:{addr[1]}"

def sign_up(username, pw_tuple):
    if username in users:
        return {"type":"SIGNUP_FAIL","body":{"reason":"username_taken"}}
    salt, dh = pw_tuple
    users[username] = (salt, dh)
    print(f"[{now('server')}] Registered user: {username}")
    return {"type":"SIGNUP_OK"}

def handle_packet(data, addr, sock):
    key = addr_key(addr)
    try:
        msg = deserialize(data)
        mtype = msg.get("type")
        body = msg.get("body", {})
    except Exception:
        sock.sendto(serialize({"type":"ERROR","body":{"reason":"bad_data"}}), addr)
        return

    # SIGNUP (unchanged)
    if mtype == "SIGNUP":
        resp = sign_up(body.get("username",""), [body.get("salt"), body.get("dh")])
        sock.sendto(serialize(resp), addr)
        return

    # — SIGNIN challenge–response ——
    if mtype == "SIGNIN_REQUEST":
        username = body.get("username","")
        rec = users.get(username)
        if not rec:
            sock.sendto(serialize({
                "type" :"SIGNIN_FAIL",
                "body" :{"reason": "username_does_not_exist"}
            }), addr)
        else:
            salt, _ = rec
            sock.sendto(serialize({
                "type": "SIGNIN_SALT",
                "body": {"salt": salt}
            }), addr)
        return

    if mtype == "SIGNIN_HASH":
        username = body.get("username","")
        incoming = body.get("hash")
        rec = users.get(username)
        if not rec:
            sock.sendto(serialize({
                "type" :"SIGNIN_FAIL",
                "body" :{"reason": "username_does_not_exist"}
            }), addr)
        else:
            salt, stored = rec
            # incoming is already the PBKDF2-derived key
            if hmac.compare_digest(stored, incoming):
                sessions[key] = {"username": username}
                print(sessions)
                print(f"[{now('server')}] {username} signed in from {key}")
                sock.sendto(serialize({"type":"SIGNIN_OK"}), addr)
            else:
                sock.sendto(serialize({
                    "type":"SIGNIN_FAIL",
                    "body":{"reason":"password_doesnt_match"}
                }), addr)
        return

    # GREETING (only allowed if authenticated)
    if mtype == "GREETING":
        if key not in sessions:
            return
        username = sessions[key]["username"]
        welcome = {"type":"GREETING_ACK","from":"SERVER","body":f"Welcome, {username}!"}
        sock.sendto(serialize(welcome), addr)
        return

    # MESSAGE (only allowed if authenticated)
    if mtype == "MESSAGE":
        if key not in sessions:
            sock.sendto(serialize({"type":"ERROR","body":{"reason":"not_authenticated"}}), addr)
            return
        user = sessions[key]["username"]
        text = body
        for client_key in sessions:
            ip, port = client_key.split(":")
            sock.sendto(serialize({
                "type":"MESSAGE",
                "from": key,
                "body": text,
                "time": now("client"),
                "username": user
            }), (ip, int(port)))
        print(f"[{now('server')}] Broadcast from {user}@{key}: {text}")
        return

    # unknown
    sock.sendto(serialize({"type":"ERROR","body":{"reason":"unknown_type"}}), addr)

def start_server(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    print(f"[{now('server')}] Listening on {ip}:{port}")
    while True:
        data, addr = s.recvfrom(BUF_SZ)
        handle_packet(data, addr, s)

if __name__ == "__main__":
    if len(sys.argv)!=3:
        print("Usage: python ChatServer.py <ip> <port>")
        sys.exit(1)
    start_server(sys.argv[1], int(sys.argv[2]))
