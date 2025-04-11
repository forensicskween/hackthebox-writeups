from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad


class Graphy:
    Iterations = 2
    KeySize = 256  # bits
    Salt = bytes([21, 204, 127, 153, 3, 237, 10, 26, 19, 103, 23, 31, 55, 49, 32, 57])

    @staticmethod
    def encrypt(data: bytes, password: str) -> bytes:
        return Graphy._crypt(AES, data, password, encrypt=True)

    @staticmethod
    def decrypt(data: bytes, password: str) -> bytes:
        return Graphy._crypt(AES, data, password, encrypt=False)

    @staticmethod
    def _crypt(cipher_cls, data: bytes, password: str, encrypt: bool) -> bytes:
        key_len = Graphy.KeySize // 8  # 32 bytes
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2(password_bytes, Graphy.Salt, dkLen=key_len + 16, count=Graphy.Iterations)
        key = kdf[:key_len]
        iv = kdf[key_len:key_len + 16]

        cipher = cipher_cls.new(key, AES.MODE_CBC, iv)

        if encrypt:
            padded_data = pad(data, AES.block_size)
            return cipher.encrypt(padded_data)
        else:
            decrypted = cipher.decrypt(data)
            return unpad(decrypted, AES.block_size)
