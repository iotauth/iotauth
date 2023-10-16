import sys
import socket
import selectors
import types
import subprocess
import time
from datetime import datetime


# TODO: Load config

filesystemManager_dir = {"name" : "", "purpose" : "", "number_key":"", "auth_pubkey_path":"", "privkey.path":"", "auth_ip_address":"", "auth_port_number":"", "port_number":"", "ip_address":"", "network_protocol":""}

def load_config(path):
    f = open(path, 'r')
    while True:
        line = f.readline()
        if not line: break
        if line.split("=")[0] == "name":
            filesystemManager_dir["name"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "purpose":
            filesystemManager_dir["purpose"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "number_key":
            filesystemManager_dir["number_key"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "auth_pubkey_path":
            filesystemManager_dir["auth_pubkey_path"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "privkey.path":
            filesystemManager_dir["privkey.path"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "auth_ip_address":
            filesystemManager_dir["auth_ip_address"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "auth_port_number":
            filesystemManager_dir["auth_port_number"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "port_number":
            filesystemManager_dir["port_number"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "ip_address":
            filesystemManager_dir["ip_address"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "network_protocol":
            filesystemManager_dir["network_protocol"] = line.split("=")[1].strip("\n")
        else:
            break
    f.close()
load_config(sys.argv[1])
print(filesystemManager_dir)

sel = selectors.DefaultSelector()

def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    global payload_max_num
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(bytes_num)  # Should be ready to read
        if recv_data:
            print(recv_data)
        # TODO: Get session key (Handshakes of entity server, OpenSSL 3.0)
            if recv_data[0] == 0:
                print("Good")
            elif recv_data[0] == 1:
                data.outb += "Hello"
                sent = sock.send(data.outb) 
                data.outb = data.outb[sent:]
        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)

host, port = filesystemManager_dir["ip_address"], int(filesystemManager_dir["port_number"])

lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((host, port))
lsock.listen()
print(f"Listening on {(host, port)}")
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    lsock.close()
    sel.close()
    print("Finished")


# TODO: Send the message and receive the message -> Success of the secure communication
# TODO: Apply SST to communication between file system manager and entities