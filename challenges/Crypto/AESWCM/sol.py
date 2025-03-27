from pwn import * 
from Crypto.Util.strxor import strxor
import sys

def get_conn(args):
    if 'python' in args:
        conn = process(args.split(' '))
    else:
        host,port = args.split(':')
        conn = remote(host,port)
    return conn


#https://github.com/jvdsn/crypto-attacks/blob/master/attacks/cbc_mac/length_extension.py
def attack(m1, t1, m2, t2):
    m3 = bytearray(m1)
    m3 += strxor(t1, m2[:16])
    for i in range(16, len(m2), 16):
        m3 += m2[i:i + 16]
    return m3, t2

def forge(conn):
	pt1 = '00000000000100000000000000000000000000000000'
	pt2 = '00000000000101010101010101010101010101010101'
	m1 = b'Property: ' + bytes.fromhex(pt1)
	m2 = b'Property: ' + bytes.fromhex(pt2)
	conn.sendlineafter(b"Property: ", str(pt1).encode())
	t1 = bytes.fromhex(conn.recvline().decode().strip())
	conn.sendlineafter(b"Property: ", str(pt2).encode())
	t2 = bytes.fromhex(conn.recvline().decode().strip())
	m3,_= attack(m1, t1, m2,t2)
	m3_ = bytes(m3)[10:].hex()
	return m3_

def solve(conn_params):
	global conn
	conn = get_conn(conn_params)
	forged = forge(conn)
	conn.sendlineafter(b"Property: ", str(forged).encode())
	res = conn.recvline().decode().strip()
	flag = conn.recvline().decode().strip()
	return flag 


if __name__ == "__main__":
	flag = solve(sys.argv[1])
	print(flag)
	#HTB{AES_cu570m_m0d35_4nd_hm4cs_423_fun}

