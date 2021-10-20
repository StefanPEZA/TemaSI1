from __future__ import annotations

import socket
from crypto_utils import *
from config import *


def get_mode_of_operation(conn: socket.socket):
    mode = conn.recv(3).decode()
    print("Modul de operare ales este: {}\n".format(mode))
    return mode


def get_encrypted_key(conn: socket.socket):
    K_encrypted = conn.recv(16)
    print("Cheia primita de la nodul A: {}\n".format(K_encrypted))
    return K_encrypted
    

def get_decrypted_key(K_encrypted):
    K = decrypt_128bit(K_encrypted, K_PRIM)
    print(f"Cheia decriptata: {K}\n")
    return K
    
    
def get_file_message(conn: socket.socket):
    size = conn.recv(4)
    size = int.from_bytes(size, 'big')
    message = conn.recv(size)
    return message


def decrypt_message_with_mode(mode, message, K):
    mode_class : BaseMode = None
    if mode == ECB:
        mode_class = Mode_ECB(K)
    elif mode == OFB:
        mode_class = Mode_OFB(K, IV)
    print(f"Mesajul de decriptat: {message}\n")
    print(f"Modul folosit pentru decriptarea mesajului: {mode_class.ID}\n")
    decrypted_msg = mode_class.decrypt(message)
    return decrypted_msg


def handle_connection(conn : socket.socket):
    # preia modul de operatie de la nodul A
    mode = get_mode_of_operation(conn)
    
    # preia cheia encriptatea de la nodul A
    K_encrypted = get_encrypted_key(conn)
    K = get_decrypted_key(K_encrypted) 
    
    #trimite semnalul de start nodului A
    conn.sendall("START".encode())
    
    #preia mesajul encriptat de la nodul A si il decripteaza
    message = get_file_message(conn)
    decrypted_msg = decrypt_message_with_mode(mode, message, K)
    print("Mesajul primit de la A:\n {}".format(decrypted_msg.decode(errors="ignore")))
    

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_B))
        s.listen()
        conn, _ = s.accept()
        handle_connection(conn)
            
if __name__ == "__main__":
    start_server()