from __future__ import annotations

import socket
from crypto_utils import *
from config import *


def handle_connection(conn : socket.socket):
    with conn:
        K = get_random_key()
        mode = conn.recv(3).decode('utf-8')
        print(f"Modul de operare ales este: {mode}")
        encrypted_key = encrypt_128bit(K, K_PRIM)
        conn.sendall(bytes(encrypted_key))


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_KM))
        s.listen()
        while True:
            conn, _ = s.accept()
            handle_connection(conn)
        
            
if __name__ == "__main__":
    start_server()
    print()
    
