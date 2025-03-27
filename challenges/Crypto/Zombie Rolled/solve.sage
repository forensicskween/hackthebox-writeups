from itertools import product
from crypto_attacks.shared.small_roots import coppersmith

from source import PrivateKey


def load_output():
    output = []
    with open('output.txt','r') as inf:
        for line in inf.readlines():
            data = eval(line.strip().split('=')[1])
            output.append(data)
    return output


def magicqq(ar):
    a,b,c = [QQ(x) for x in ar]
    return ( a+b)/(b+c) + (b+c)/(a+c) + (a+c)/(a+b)


def magicq(a,b,c):
    return ( a+b)/(b+c) + (b+c)/(a+c) + (a+c)/(a+b)

def gen_pub_equation(pub):
    p, q, r = map(ZZ, pub)
    magic_1 = magicq(p,q,r)
    P = QQ["a, b, c"]
    a, b, c = P.gens()
    eq =  magic_1-magicq(a,b,c)
    f = EllipticCurve_from_cubic(eq.numerator(), [-1, 1, 1])
    fi = f.inverse()
    G = f([p, q, r])
    aa, bb, cc = fi(2 * G)
    l = lcm(lcm(aa.denom(), bb.denom()), cc.denom())
    aa, bb, cc = ZZ(aa * l), ZZ(bb * l), ZZ(cc * l)
    assert magicq(aa,bb,cc) == magic_1
    pub = (int(aa), int(bb), int(cc))
    return f,fi,pub
  

def make_g2(pub,f):
    G2 = [QQ(pub[0])/QQ(pub[-1]), QQ(pub[1])/QQ(pub[-1]),QQ(pub[-1])/QQ(pub[-1])]
    PP=[x(list(G2)) for x  in f.defining_polynomials()]
    return PP


def recover_priv_key(pub):
    f,fi,_ = gen_pub_equation(pub)
    point_g2 = make_g2(pub,f)
    G2 = f(fi(point_g2))
    G2_div = G2.division_points(2,poly_only=True).roots()
    G = f.codomain().lift_x(G2_div[0][0])
    G_inv = fi(G)
    priv_key = (G_inv[0].numerator(),G_inv[1].numerator(),G_inv[1].denominator())
    _,_,pub_check = gen_pub_equation(priv_key)
    assert pub_check == pub
    return priv_key




def gen_eqs(ar,pr=False):
    if pr:
        ab,bc,ac = ar
    else:
        a,b,c = ar
        ab = (a+b)
        bc =  (b+c)
        ac = (a+c)
    lcd = bc*ac*ab
    f1_exp = ab*ac*ab
    f2_exp = ab*bc*bc
    f3_exp = bc*ac*ac
    return (f1_exp,f2_exp,f3_exp,lcd)

def gen_coeffs(values):
    bls,x_values,skip =[],{},{}
    for k,v in values.items():
        target_bl = 1025-v.bit_length()
        if target_bl == 0:
            skip[k] = v
            continue
        else:
            x_values[k] = v
            bls.append(range(2**(target_bl-1),2**(target_bl+1)))
    return bls,x_values,skip

def recover_primes_bruteforce(X1,X2,X3,pub):
    map_result= {'X1':X1,'X2':X2,'X3':X3}
    coeffs,x_values,skip = gen_coeffs(map_result)
    for coeff in product(*coeffs):
        result = {k:v*y for (k,v),y in zip(x_values.items(),coeff)} | skip
        result_b = -((result['X3']-result['X2'])-result['X1'])
        if result_b%2 ==0:
            result_b = result_b//2
            result_c = result['X1'] - result_b
            result_a = result['X3'] - result_c 
            if magicqq((result_a,result_b,result_c)) == magicqq(pub):
                print(f'Recovered Private Key {(result_a,result_b,result_c)}')
                return (result_a,result_b,result_c)

def recover_public_key_bruteforce(pub):
    D,N = magicqq(pub).denominator(),magicqq(pub).numerator()
    pub_a,pub_b,pub_c = pub
    G1 = gcd(D,pub_a+pub_c)
    G2 = gcd(D,pub_b+pub_a)
    G3 = gcd(D,pub_b+pub_c)

    X1 = gcd(G1,G2)
    X2 = gcd(G3,G2)
    X3 = gcd(G1,G3)
    return recover_primes_bruteforce(X1,X2,X3,pub)


def recover_message(priv,pub):
    key = PrivateKey(list(map(int,priv)),list(map(int,pub)),int(prod(priv)))
    unmixed = [key.decrypt(x) for x in mix]
    s2 =  (unmixed[0]-unmixed[1])*pow(2,-1,key.n)%key.n
    s1 =  (unmixed[0]-s2)%key.n
    r, c = key.encrypt(s1),key.encrypt(s2)

    poly.<a,b> = PolynomialRing(Zmod(key.n))
    magic_n = a^3 + 3*a^2*b + 2*a*b^2 + b^3 + 2*a^2*c + 6*a*b*c + 3*b^2*c + 3*a*c^2 + 2*b*c^2 + c^3
    magic_d = a^2*b + a*b^2 + a^2*c + 2*a*b*c + b^2*c + a*c^2 + b*c^2

    fx = (r*magic_d -magic_n)

    bounds = (2**(32*8),2**256)
    roots = coppersmith.small_roots(fx,bounds)

    for v in roots:
        m = int(v[0])
        if key.verify(m,(int(s1),int(s2))):
            print(m.to_bytes((m.bit_length() + 7) // 8,'big').decode())
                
                

if __name__ == "__main__":
    pub,mix = load_output()
    priv_brute = recover_public_key_bruteforce(pub)
    priv_ec = recover_priv_key(pub)
    assert priv_ec == priv_brute
    recover_message(priv_brute,pub)

