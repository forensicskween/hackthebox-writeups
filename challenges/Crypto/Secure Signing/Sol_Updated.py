import sys 
from pwn import remote
from hashlib import sha256

def receive_hash(message):
    conn.sendlineafter(b'> ',b'1')
    conn.sendlineafter(b"Enter your message: ",message)
    return conn.recvline().decode().strip().split(': ')[1]

def verify_hash(message,hsh):
    conn.sendlineafter(b'> ',b'2')
    conn.sendlineafter(b"Enter your message: ",message)
    conn.sendlineafter(b"Enter your message: ",hsh.encode())
    result =  conn.recvline().decode().strip()
    return result

if __name__ == "__main__":
    host,port=sys.argv[1].split(":")
    conn = remote(host,port)
    secret = b'HTB{'
    while not secret.endswith(b'}'):
        hash_dict = {sha256(bytes(len(secret)) + bytes([s])).hexdigest():bytes([s]) for s in range(256)}
        xor_ba = receive_hash(secret.decode() + '\x00')
        secret += hash_dict[xor_ba]
        print(secret.decode())
        
#HTB{r0ll1n6_0v3r_x0r_w17h_h@5h1n6_0r@cl3_15_n07_s3cur3!@#}