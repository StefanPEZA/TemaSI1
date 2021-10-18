from Crypto.Cipher import AES
import Crypto.Random as random
from config import ECB, OFB


def get_random_key():
    return random.get_random_bytes(16)

def encrypt_128bit(text, key):
    aes = AES.new(key)
    enc = aes.encrypt(text[:16])
    return enc
    
def decrypt_128bit(cryptotext, key):
    aes = AES.new(key)
    dec = aes.decrypt(cryptotext[:16])
    return dec


class BaseMode:
    def __init__(self, key, iv = None):
        self.key = key
        self.iv = iv
        
    def encrypt(self, plaintext):
        raise NotImplementedError
    
    def decrypt(self, cryptotext):
        raise NotImplementedError
    
    
class Mode_ECB(BaseMode):
    ID = ECB
    def encrypt(self, plaintext):
        enc = b''
        while plaintext:
            block = plaintext[0:16]
            block = block + b' ' * (16 - len(block))
            plaintext = plaintext[16:]
            aes = AES.new(self.key)
            enc += aes.encrypt(block)
        return enc
    
    def decrypt(self, cryptotext):
        dec = b''
        while cryptotext:
            block = cryptotext[0:16]
            block = block + b' ' * (16 - len(block))
            cryptotext = cryptotext[16:]
            aes = AES.new(self.key)
            dec += aes.decrypt(block)
        return dec


class Mode_OFB(BaseMode):
    ID = OFB
    def encrypt(self, plaintext):
        enc = b''
        iv = bytes(self.iv)
        cipher = AES.new(self.key, AES.MODE_ECB)
        while plaintext:
            block = plaintext[0:16]
            block = block + b' ' * (16 - len(block))
            plaintext = plaintext[16:]
            to_xor = cipher.encrypt(iv)
            cipherText = bytes([to_xor[i] ^ block[i] for i in range(16)])
            enc += cipherText
            iv = to_xor
        return enc
    
    def decrypt(self, cryptotext):
        dec = b''
        iv = bytes(self.iv)
        cipher = AES.new(self.key, AES.MODE_ECB)
        while cryptotext:
            block = cryptotext[0:16]
            block = block + b' ' * (16 - len(block))
            cryptotext = cryptotext[16:]
            to_xor = cipher.encrypt(iv)
            cipherText = bytes([to_xor[i] ^ block[i] for i in range(16)])
            dec += cipherText
            iv = to_xor
        return dec

