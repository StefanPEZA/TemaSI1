from __future__ import annotations

import socket
import time
from crypto_utils import *
from config import *


def encrypt_message_with_mode(mode, message, K):
    mode_class : BaseMode = None
    if mode == ECB:
        mode_class = Mode_ECB(K)
    elif mode == OFB:
        mode_class = Mode_OFB(K, IV)
    print("Mesajul care trebuie encriptat: {}\n".format(message))
    print(f"Modul folosit pentru encriptarea mesajului: {mode_class.ID}\n")
    encrypted_msg = mode_class.encrypt(message)
    return encrypted_msg


def request_from_key_manager(mode):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as kms:
        kms.connect((HOST, PORT_KM))
        kms.sendall(mode.encode())
        
        K_encrypted = kms.recv(16)
        print("Cheia primita de la nodul KM: {}\n".format(K_encrypted))
        
        K = decrypt_128bit(K_encrypted, K_PRIM)
        print("Cheia decriptata: {}\n".format(K))
        return K, K_encrypted
    
    
def send_encrypted_file_to(sock: socket.socket, mode, K):
    file_name = input("Numele fisierului pe care vreti sa-l trimiteti: ")
    try:
        with open(file_name, "rb") as f:
            file_text = f.read()
            
            encrypted_message = encrypt_message_with_mode(mode, file_text, K)
            
            file_size = len(encrypted_message)

            sock.sendall(file_size.to_bytes(4, 'big'))
            print("Mesajul encriptat: {}".format(encrypted_message))
            sock.sendall(encrypted_message)
    except FileNotFoundError:
        print("Nu s-a gasit fisierul, incercati din nou.")
        send_encrypted_file_to(sock, mode, K)
    
    
def connect_with_B(mode, K, K_encrypted):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT_B))
        s.sendall(mode.encode())
        s.sendall(K_encrypted)
        
        start_signal = s.recv(5)
        print(f'Semnalul a fost primit de la B: {start_signal.decode()}\n')
        
        send_encrypted_file_to(s, mode, K)
        

if __name__ == "__main__":
    op_mode = input("Ce mod doriti sa folositi: \n1. ECB\n2. OFB\n>> ")
    if op_mode == "1":
        op_mode = ECB
    else: op_mode = OFB
    
    K, K_encrypted = request_from_key_manager(op_mode)
    
    connect_with_B(op_mode, K, K_encrypted)