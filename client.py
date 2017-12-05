#!/usr/bin/env python3.5

import select
import socket
import sys

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
    s.settimeout(2)

    # Connect to remote host
    try:
        s.connect((host, port))
    except:
        print("Unable to connect")
        sys.exit()

    s.send(username.encode("utf-8"))
    data = s.recv(4096)
    if not data == b'OK':
        if data[1:] == b'USERNAME_TAKEN':
            print("%s username already taken" % username)
            sys.exit()
    print("Connected to chat with username %s" % username)
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
