import os 
import base64
from bs4 import BeautifulSoup

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b


def b64encode_int(n):
    # Convert integer to big-endian bytes, then base64 encode
    return base64.b64encode(l2b(n)).decode('ascii')

def b64decode_int(b64_string):
    # Decode base64 string to bytes, then convert to integer
    return b2l(base64.b64decode(b64_string))

class Stego:
    @staticmethod
    def create_keys(bits: int):
        key1 = RSA.generate(bits)
        key2 = Stego.key2xml(key1)
        return key1,key2
    
    @staticmethod
    def key2xml(key):
        modulus = b64encode_int(key.n)
        exponent = b64encode_int(key.e)
        p = b64encode_int(key.p)
        q = b64encode_int(key.q)
        dp = b64encode_int(key.d % (key.p - 1))
        dq = b64encode_int(key.d % (key.q - 1))
        inverse_q = b64encode_int(key.u)  # u is inverse of q mod p
        d = b64encode_int(key.d)

        # Build XML string in Microsoft RSA format
        xml = f"""<RSAKeyValue><Modulus>{modulus}</Modulus><Exponent>{exponent}</Exponent><P>{p}</P><Q>{q}</Q><DP>{dp}</DP><DQ>{dq}</DQ><InverseQ>{inverse_q}</InverseQ><D>{d}</D></RSAKeyValue>"""
        return xml

    @staticmethod
    def xml2key(xml_bytes):
        soup = BeautifulSoup(xml_bytes,'xml')
        priv_key = {}
        for tag in soup.find('RSAKeyValue').find_all(recursive=False):
            priv_key[tag.name] = b64decode_int(tag.text.strip())
        privkey = RSA.construct((priv_key['Modulus'],priv_key['Exponent'],priv_key['D'],priv_key['P'],priv_key['Q']))
        return privkey
    
    @staticmethod
    def encrypt(plaintext: bytes, key: RSA.RsaKey):
        cipher = PKCS1_v1_5.new(key)
        return cipher.encrypt(plaintext)

    @staticmethod
    def decrypt(ciphertext: bytes, key: RSA.RsaKey):
        cipher = PKCS1_v1_5.new(key)
        sentinel = os.urandom(16)
        decrypted = cipher.decrypt(ciphertext,sentinel)
        if decrypted!=sentinel:
            return decrypted
        else:
            raise ValueError("Faulty Decryption")
    
    
    

    
    




