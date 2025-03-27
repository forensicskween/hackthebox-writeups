from pwn import remote
import base64
from Crypto.Util.number import long_to_bytes as l2b
from re import search as rsearch
from math import prod
from sympy import primefactors as prime_factors

golden_ratio = 2654435761
admin = int.from_bytes(b'System_Administrator','big')
hash_var = lambda key: (((key % golden_ratio) * golden_ratio) >> 32)
target_h = hash_var(admin)

def parse_equation(equations):
    h_factors = []
    for eq in equations:
        rnd,result = int(eq.split(', ')[1]),int(eq.split('= ')[-1])
        h_factors.append((pow(rnd,-1,golden_ratio)*result)%golden_ratio)
    return prod(h_factors)

def recover_n():
    conn.sendlineafter(b'Option >> ',b'2')
    conn.recvuntil(b'following equations:\n')
    equations = eval(conn.recvline().decode().strip())
    h_n = parse_equation(equations)
    conn.sendlineafter(b"Enter the hash(N): ",str(h_n).encode())
    result = conn.recvline().decode().strip()
    if result == '[+] Captcha successful!':
        e,n = eval(conn.recvline().decode().strip().split('=')[1])
        return e,n
    return False


def find_h_factor(h_factor):
    start_value = (h_factor*(2**32))//golden_ratio
    for i in range(1,2**16):
        try:
            H = (start_value+i*golden_ratio+1)
            if hash_var(H) == h_factor:
                if not rsearch('[^a-zA-Z0-9]', l2b(H).decode()):
                    return l2b(H).decode()
        except:
            continue


def register(username):
    conn.sendlineafter(b'Option >> ',b'0')
    conn.sendlineafter(b"Enter a username: ",username)
    res = conn.recvline().decode().strip()
    if res[:21]=='Your session token is':
        token_int = int(base64.b64decode(res[24:-1]).decode())
        return token_int
    return False

def login(token):
    token_b64 = base64.b64encode(str(token).encode())
    conn.sendlineafter(b'Option >> ',b'1')
    conn.sendlineafter(b"Enter your username: ",b'System_Administrator')
    conn.sendlineafter(b"Enter your authentication token: ",token_b64)
    res = conn.recvline().decode().strip()
    return res

conn = remote('94.237.59.30','55606')
e,n = recover_n()
user_names = [find_h_factor(h_factor) for h_factor in prime_factors(target_h)]
token_ints = [register(user) for user in user_names]
assert pow(prod(token_ints)%n,e,n) == target_h
result = login(prod(token_ints)%n)
print(result)
