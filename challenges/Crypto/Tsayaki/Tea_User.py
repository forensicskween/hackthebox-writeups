import os
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1
        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)
    
    def decrypt_block(self,block,round=32):
        K = self.KEY
        result =[]
        v0 =  b2l(block[:4])
        v1 =  b2l(block[4:])
        delta = 0x9E3779B9
        sumd = (delta * round) & 0xFFFFFFFF
        for j in range(round):
            v1 -= ((v0 << 4) + K[2]) ^ (v0 + sumd) ^ ((v0 >> 5) + K[3])
            v1 &= 0xFFFFFFFF
            v0 -= ((v1 << 4) + K[0]) ^ (v1 + sumd) ^ ((v1 >> 5) + K[1])
            v0 &= 0xFFFFFFFF
            sumd -= delta
        result = l2b(v0)+l2b(v1)
        return result

    def decrypt(self, msg):
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        pt = b''
        if self.mode == Mode.ECB:
            for ct in blocks:
                pt += self.decrypt_block(ct)
        elif self.mode == Mode.CBC:
            X = self.IV
            for ct in blocks:
                enc_block = self._xor(self.decrypt_block(ct),X)
                pt += enc_block
                X = ct
        #return unpad(pt, self.BLOCK_SIZE//8)
        return unpad(pt, self.BLOCK_SIZE//8)
        #return pt

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct
