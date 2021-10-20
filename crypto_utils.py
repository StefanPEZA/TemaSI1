from Crypto.Cipher import AES
import Crypto.Random as random
from config import ECB, OFB
from abc import abstractclassmethod


def get_random_key():
    # genereaza un sir de bytes random de lungime 16 (128 biti)
    return random.get_random_bytes(16)

def encrypt_128bit(text, key):
    # encripteaza un block de 128 biti
    aes = AES.new(key)
    enc = aes.encrypt(text[:16])
    return enc
    
def decrypt_128bit(cryptotext, key):
    # decripteaza un block de 128 biti
    aes = AES.new(key)
    dec = aes.decrypt(cryptotext[:16])
    return dec


class BaseMode:
    def __init__(self, key, iv = None):
        self.key = key
        self.iv = iv
        
    @abstractclassmethod
    def encrypt(self, plaintext):
        raise NotImplementedError
    
    @abstractclassmethod
    def decrypt(self, cryptotext):
        raise NotImplementedError
    
    
class Mode_ECB(BaseMode):
    ID = ECB
    def encrypt(self, plaintext):
        enc = b''
        while plaintext:
            block = plaintext[0:16]  # encriptia se face pe un block plaintext de cate 16 bytes/128 biti
            block = block + b' ' * (16 - len(block))
            plaintext = plaintext[16:]
            enc += encrypt_128bit(block, self.key)
        return enc
    
    def decrypt(self, cryptotext):
        dec = b''
        while cryptotext:
            block = cryptotext[0:16] # decriptarea se face pe un block din cryptotext de cate 16 bytes/128 biti
            block = block + b' ' * (16 - len(block))
            cryptotext = cryptotext[16:]
            dec += decrypt_128bit(block, self.key)
        return dec


class Mode_OFB(BaseMode):
    ID = OFB
    def encrypt(self, plaintext):
        enc = b''
        iv = bytes(self.iv)
        while plaintext:
            # se extrage un block
            block = plaintext[0:16]
            block = block + b' ' * (16 - len(block))
            plaintext = plaintext[16:]
            
            # se face encriptia vectorului de initializare
            to_xor = encrypt_128bit(iv, self.key)
            
            # se face xor intre VI encriptat si block-ul de plaintexts
            cipherText = bytes([to_xor[i] ^ block[i] for i in range(16)])
            
            # se adauga block-ul la output
            enc += cipherText
            
            # se salveaza VI encriptat pentru urmatoarea iteratie
            iv = to_xor
        return enc
    
    def decrypt(self, cryptotext):
        # acelasi lucru ca la encriptie, doar ca aici inputul este cryptotext-ul 
        dec = b''
        iv = bytes(self.iv)
        while cryptotext:
            block = cryptotext[0:16]
            block = block + b' ' * (16 - len(block))
            cryptotext = cryptotext[16:]
            to_xor = encrypt_128bit(iv, self.key)
            cipherText = bytes([to_xor[i] ^ block[i] for i in range(16)])
            dec += cipherText
            iv = to_xor
        return dec

