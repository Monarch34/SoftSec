import socket
import sys
import os
import hashlib
import hmac
import pickle
from datetime import datetime

# Server configuration
PORT    = 9090
BUF_SZ  = 4096

# In-memory stores
users    = {}   # username → (salt: bytes, hash: bytes)
sessions = {}   # "ip:port" → {"username":…, "password":…}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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


def sign_up(username, password):
    if username in users:
        return {"type":"SIGNUP_FAIL","body":{"reason":"username_taken"}}
    if len(password) < 8:
        return {"type":"SIGNUP_FAIL","body":{"reason":"password_too_short"}}
    salt, dh = hash_pw(password)
    users[username] = (salt, dh)
    print(f"[{now()}] Registered user: {username}")
    return {"type":"SIGNUP_OK"}


def sign_in(username, password, key):
    rec = users.get(username)
    if not rec:
        return {"type":"SIGNIN_FAIL"}
    salt, stored = rec
    _, incoming = hash_pw(password, salt)
    if hmac.compare_digest(stored, incoming):
        sessions[key] = {"username":username, "password":password}
        print(f"[{now()}] {username} signed in from {key}")
        return {"type":"SIGNIN_OK"}
    return {"type":"SIGNIN_FAIL","body":{"reason":"password_doesnt_match"}}


def handle_packet(data, addr, sock):
    key = addr_key(addr)
    try:
        msg = deserialize(data)
        mtype = msg.get("type")
        body = msg.get("body", {})
    except Exception:
        sock.sendto(serialize({"type":"ERROR","body":{"reason":"bad_data"}}), addr)
        return

    # SIGNUP
    if mtype == "SIGNUP":
        resp = sign_up(body.get("username",""), body.get("password",""))
        sock.sendto(serialize(resp), addr)
        return

    # SIGNIN
    if mtype == "SIGNIN":
        resp = sign_in(body.get("username",""), body.get("password",""), key)
        sock.sendto(serialize(resp), addr)
        if resp["type"] == "SIGNIN_OK":
            # upon authentication client should send GREETING next
            pass
        return

    # GREETING (only allowed if authenticated)
    if mtype == "GREETING":
        if key not in sessions:
            # discard unauthenticated greetings
            return
        # acknowledge greeting
        username = sessions[key]["username"]
        welcome = {"type":"GREETING_ACK","from":"SERVER","body":f"Welcome, {username}!"}
        sock.sendto(serialize(welcome), addr)
        return

    # MESSAGE (only allowed if authenticated)
    if mtype == "MESSAGE":
        if key not in sessions:
            sock.sendto(serialize({"type":"ERROR","body":{"reason":"not_authenticated"}}), addr)
            return
        text = body
        # broadcast to all authenticated sessions
        for client_key in sessions:
            ip, port = client_key.split(":")
            sock.sendto(serialize({"type":"MESSAGE","from":key,"body":text, "time":now()}), (ip, int(port)))
        print(f"[{now()}] Broadcast from {key}: {text}")
        return

    # unknown
    sock.sendto(serialize({"type":"ERROR","body":{"reason":"unknown_type"}}), addr)


def start_server(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    print(f"[{now()}] Listening on {ip}:{port}")
    while True:
        data, addr = s.recvfrom(BUF_SZ)
        handle_packet(data, addr, s)

if __name__ == "__main__":
    if len(sys.argv)!=3:
        print("Usage: python ChatServer.py <ip> <port>")
        sys.exit(1)
    start_server(sys.argv[1], int(sys.argv[2]))
