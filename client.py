#!/usr/bin/env python3.5

import select
import socket
import sys
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

passphrase = b"EtienneLeGros1000"

def prompt(username):
    sys.stdout.write("[%s] " % username)
    sys.stdout.flush()

def chat_client():
    if (len(sys.argv) < 4):
        print("Usage: ./client.py <hostname> <port> <username>")
        sys.exit()

    host = sys.argv[1]
    port = int(sys.argv[2])
    username = sys.argv[3]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)

    private_key = None
    public_key = None

    key_path = username + "/.keys/"
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    
    if not os.path.isfile(key_path + "key.pub"):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private = open(key_path + "key", "wb")
        private.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        ))
        if os.path.isfile(key_path + "key.pub"):
            os.remove(key_path + "key.pub")
        public = open(key_path + "key.pub", "wb")
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public.write(public_key)
    else:
        public = open(key_path + "key.pub", "rb")
        private = open(key_path + "key", "rb")
        private_key = private.read()
        public_key = public.read()
    # Connect to remote host
    try:
        s.connect((host, port))
    except:
        print("Unable to connect")
        sys.exit()

    s.send(username.encode("utf-8"))
    data = s.recv(4096)
    if not data[1:] == b'OK':
        if data[1:] == b'USERNAME_TAKEN':
            s.send(str.encode("NOK"))
            print("%s username already taken" % username)
            sys.exit()
        else:
            s.send(str.encode("NOK"))
            print("ERROR")
            sys.exit()
    s.send(str.encode("OK"))
    if not os.path.exists(key_path):
        os.makedirs(key_path)
    data = s.recv(4096)
    # write server public key in file
    if os.path.isfile(key_path + " server.pub"):
        os.remove(key_path + "server.pub")
    server_pkey = data
    server_file_pkey = open(key_path + "server.pub", "wb")
    server_file_pkey.write(server_pkey)

    #send user public key
    s.send(public_key)
    

    prompt(username)
    while True:
        socket_list = [sys.stdin, s]

        # List readable sockets
        ready_to_read, ready_to_write, in_error = select.select(socket_list, [], [])

        for sock in ready_to_read:
            if sock == s:
                # Receiving message from server
                data = sock.recv(4096)
                if not data:
                    print("\nDisconnected from server")
                    sys.exit()
                else:
                    sys.stdout.write("\r" + ' ' * (len(username) + 2) + data.decode())
                    prompt(username)
            else:
                msg = sys.stdin.readline()
                s.send(msg.encode("utf-8"))
                prompt(username)

if __name__ == "__main__":
    sys.exit(chat_client())
