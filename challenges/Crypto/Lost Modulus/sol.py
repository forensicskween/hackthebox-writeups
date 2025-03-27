from sage.all import *

def low_exponent(ct):
	pt = ZZ(ct).nth_root(3)
	flag = bytes.fromhex(hex(pt)[2:])
	return flag.decode()

def solve(fname):
	with open(fname,'r') as inf:
		data = inf.read()
	ct = int(data.split(': ')[-1].strip(),16)
	flag = low_exponent(ct)
	return flag

flag = solve('output.txt')
print(flag)
#HTB{n3v3r_us3_sm4ll_3xp0n3n7s_f0r_rs4}
