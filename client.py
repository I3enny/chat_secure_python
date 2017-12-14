#!/usr/bin/env python3.5

import select
import socket
import sys
import os
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

passphrase = b"EtienneLeGros1000"
private_key = None
public_key_serv = None
cipher = None

def my_encode(msg):
    return base64.b64encode(bytes(msg, "utf-8"))

def my_decode(msg):
    return base64.b64decode(msg).decode("utf-8", "ignore")

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

    public_key_bytes = None
    if not os.path.isfile(".keys/" + username + ".priv"):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private = open(".keys/" + username + ".priv", "wb")
        private.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        ))
        if os.path.isfile(".keys/" + username + ".pub"):
            os.remove(".keys/" + username + ".pub")
        public = open(".keys/" + username + ".pub", "wb")
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public.write(public_key_bytes)
    else:
        public = open(".keys/" + username + ".pub", "rb")
        private = open(".keys/" + username + ".priv", "rb")
        private_key = serialization.load_pem_private_key(
                private.read(),
                password=passphrase,
                backend=default_backend()
        )
        public_key_bytes = public.read()
    # Connect to remote host
    try:
        s.connect((host, port))
    except:
        print("Unable to connect")
        sys.exit()

    s.send(my_encode(username))
    data = s.recv(4096)
    data = my_decode(data)
    print(data[1:])
    if not data[1:] == 'OK':
        if data[1:] == 'USERNAME_TAKEN':
            s.send(my_encode("NOK"))
            print("%s username already taken" % username)
            sys.exit()
        else:
            s.send(my_encode("NOK"))
            print("ERROR")
            sys.exit()
    s.send(my_encode("OK"))
    if not os.path.exists(".keys"):
        os.makedirs(".keys")
    data = s.recv(4096)
    # write server public key in file
    if os.path.isfile(".keys/server.pub"):
        os.remove(".keys/server.pub")
    server_pkey = data
    server_file_pkey = open(".keys/server.pub", "wb")
    server_file_pkey.write(server_pkey)
    public_key_serv = serialization.load_pem_public_key(
            server_pkey,
            backend=default_backend()
    )
    #send user public key
    s.send(public_key_bytes)

    prompt(username)
    while True:
        socket_list = [sys.stdin, s]

        # List readable sockets
        ready_to_read, ready_to_write, in_error = select.select(socket_list, [], [])

        for sock in ready_to_read:
            if sock == s:
                # Receiving message from server
                data = sock.recv(4096)
                data = private_key.decrypt(
                        data,
                        padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )
                )
                if not my_decode(data):
                    print("\nDisconnected from server")
                    sys.exit()
                else:
                    data = my_decode(data)
                    sys.stdout.write("\r" + ' ' * (len(username) + 2) + data)
                    prompt(username)
            else:
                msg = sys.stdin.readline()
                msgencrypt = public_key_serv.encrypt(
                    my_encode(msg),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )
                )
                s.send(msgencrypt)
                prompt(username)

if __name__ == "__main__":
    sys.exit(chat_client())
