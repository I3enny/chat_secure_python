#!/usr/bin/env python3.5

import os
import select
import socket
import sys
import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.fernet import Fernet

host = ''
port = 9009
socket_list = []
recv_buffer = 4096
passphrase = b"EtienneLeGros1000"
private_key = None
users = {}
users_ciphers = {}

def create_sym(socket, user):
    sym_key = Fernet.generate_key()
    users_ciphers[user] = Fernet(sym_key)
    print(sym_key)
    send_msg_crypt_asym(socket, str(sym_key, "utf-8"))

def my_encode(msg):
    return base64.b64encode(bytes(msg, "utf-8"))

def my_decode(msg):
    return base64.b64decode(msg).decode("utf-8", "ignore")

def remove_user(sock):
    for name, s in users.items():
        if s == sock:
            del users[name]
            break
    socket_list.remove(sock)

def get_user(sock):
    for name, s in users.items():
        if s == sock:
            return name
    return None

def send_msg(socket, message):
    msg = "\r" + message
    try:
        socket.send(my_encode(msg))
    except:
        # Broken socket connection
        socket.close()
        # Broken socket, remove it
        if socket in socket_list:
            remove_user(socket)

def send_msg_crypt(socket, message):
    msg = "\r" + message
    try:
        user = get_user(socket)
        msgencrypt = users_ciphers[user].encrypt(my_encode(msg))
        socket.send(msgencrypt)
    except:
        print("AH!")
        socket.close()
        # Broken socket, remove it
        if socket in socket_list:
            remove_user(socket)


def send_msg_crypt_asym(socket, message):
    msg = "\r" + message
    try:
        user = get_user(socket)
        usr_key_file = open("server/clientskeys/" + user + ".pub", "rb")
        usr_key = serialization.load_pem_public_key(
            usr_key_file.read(),
            backend=default_backend()
        )
        encrypt = usr_key.encrypt(
            my_encode(msg),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        usr_key_file.close()
        socket.send(encrypt)
    except:
        print(sys.exc_info[0])
        print("Error in crypt")
        # Broken socket connection
        socket.close()
        # Broken socket, remove it
        if socket in socket_list:
            remove_user(socket)

# Broadcast chat messages to all connected clients
def broadcast(server_socket, sock, message):
    print(message[:-1])
    for socket in socket_list:
        # Send message only to peer
        if socket != server_socket and socket != sock:
            send_msg_crypt(socket, message)

# Basic cmd parsing
def cmd(server_socket, sock, message):
    cmd = message.split(' ')
    if cmd[0] == 'msg':
        send_msg_crypt(sock, "Msg not implemented\n")
    elif cmd[0] == 'users':
        msg = "Users:\n"
        for u in users:
            msg += "\t" + u + "\n"
        send_msg_crypt(sock, msg)
    else:
        send_msg_crypt(sock, "Cmd unknown\n")

def chat_server():
    private_key = None
    if not os.path.exists("server"):
        os.makedirs("server")
    if not os.path.exists("server/clientskeys"):
        os.makedirs("server/clientskeys")
    if not os.path.isfile("server/key.pem"):
        # Generate server private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open("server/key.pem", "wb") as f:

            # Generate server private key
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
            ))
            public = open("server/key.pub.pem", "wb")
            public_key = private_key.public_key()
            public.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
             ))
    else:
        with open("server/key.pem", "rb") as f:
            private_key = load_pem_private_key(f.read(), passphrase, backend=default_backend())

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(10)

    # Add server socket object to the list of readable connecions
    socket_list.append(server_socket)

    print("Chat server started on port %d"  % port)

    while True:
        # Get the list sockets which are ready to be read through select
        # 4th arg, time_out = 0 : poll and never block
        ready_to_read, ready_to_write, in_error = select.select(socket_list, [], [], 0)

        for sock in ready_to_read:
            # New connection request received
            if sock == server_socket:
                sockfd, addr = server_socket.accept()
                data = sockfd.recv(recv_buffer)
                data = my_decode(data)
                if data:
                    if users.get(data):
                        send_msg(sockfd, "USERNAME_TAKEN")
                    else:
                        send_msg(sockfd, "OK")
                        socket_list.append(sockfd)
                        users[data] = sockfd
                        response = sockfd.recv(4096)
                        if (my_decode(response) == "OK"):
                            # Sending server public key
                            pkey = open("server/key.pub.pem", "rb")
                            keymsg = pkey.read();
                            sockfd.send(keymsg)
                            # Receiving client public key
                            response = sockfd.recv(4096)
                            username = get_user(sockfd)
                            keyname = "server/clientskeys/" + username + ".pub"
                            if (os.path.exists(keyname)):
                                os.remove(keyname)
                            clientkey = open(keyname, "wb")
                            clientkey.write(response)
                            clientkey.close()
                        create_sym(sockfd, username)
                        broadcast(server_socket, sockfd, "%s connected\n" % data)

            # Message from client, not new connecion
            else:
                # Process data received from client
                try:
                    # Receiving data from socket
                    data = sock.recv(recv_buffer)
                    user = get_user(sock)
                    data = users_ciphers[user].decrypt(data)
                    data = my_decode(data)
                    if data:
                        # Socket not empty
                        if data[0] == '/':
                            cmd(server_socket, sock, data[1:-1])
                        else:
                            broadcast(server_socket, sock, "[" + user + "] " + data)
                    else:

                        # Remove broken socket
                        if sock in socket_list:
                            remove_user(sock)

                        # Connection broken
                        broadcast(server_socket, sock, "User %s disconnected\n" % user)
                except ValueError:
                    user = get_user(sock)
                    if sock in socket_list:
                        remove_user(sock)
                    broadcast(server_socket, sock, "Error : User %s disconnected\n" % user)
                    continue

    server_socket.close()

if __name__ == "__main__":
    sys.exit(chat_server())
