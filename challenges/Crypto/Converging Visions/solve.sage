
from pwn import remote 
from random import randint

class PRNG:

    def __init__(self, p, mul1, mul2):
        self.mod = p * 6089788258325039501929073418355467714844813056959443481824909430411674443639248386564763122373451773381582660411059922334086996696436657009055324008041039
        self.exp = 2
        self.mul1 = mul1
        self.mul2 = mul2
        self.inc = int.from_bytes(b'Coordinates lost in space', 'big')
        self.seed = randint(2, self.mod - 1)

    def rotate(self):
        self.seed = (self.mul1 * pow(self.seed, 3) + self.mul2 * self.seed +
                     self.inc) % self.mod
        return self.seed, pow(self.seed, self.exp, self.mod)



def recover_modulus(t):
    def is_leq(m):
        t.sendlineafter(b'> ',b'1')
        t.recvline()
        t.sendlineafter(b'x : ', str(m).encode())
        res = t.recvline().decode().strip()
        return res == 'Coordinate greater than curve modulus'
    l, u = 0, 2**256
    m = 2**255
    while l + 1 != u:
        if is_leq(m): u = m
        else: l = m
        m = (u + l) // 2
    return m+1


def find_points(t):
    def is_valid(x):
        t.sendlineafter(b'> ', b'1')
        t.recvline()
        t.sendlineafter(b'x : ', str(x).encode())
        res = t.recvline().decode().strip()
        if "Point confirmed on curve"  not in res:
            return False
        if eval(res)[-1] == 0:
            return False
        return eval(res)[1:]
    
    points = []
    while len(points) != 2:
        x = randint(0, p - 1)
        point = is_valid(x)
        if point:
            points.append(point)
    return points

def recover_parameters(P1,P2):
    (x1,y1),(x2,y2) = P1,P2

    Poly.<a,b> = PolynomialRing(GF(p))

    p1 = (x1^3 + a*x1 + b) - y1^2
    p2 = (x2^3 + a*x2 + b) - y2^2

    a = (p1-p2).univariate_polynomial().roots()[0][0]
    b = p1.subs(a=a).univariate_polynomial().roots()[0][0]

    E = EllipticCurve(GF(p),[a,b])

    assert E(ZZ(x1),ZZ(y1))
    assert E(ZZ(x2),ZZ(y2))

    order = E.order()

    print(f'a : {a}')
    print(f'b : {b}')
    print(f'Order : {order}')

    return E,a,b

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)


def get_original_seed_roots(seed):
    inc = 423298202838516040093965914645844180330692880951980532523877
    poly.<s> = PolynomialRing(F)
    fx = (a * pow(s, 3) + b * s + inc)^2
    fx = fx - seed
    return  [x[0] for x in fx.roots()]


host,port = '',''

t = remote(host,port)
p = recover_modulus(t)
print(F'Modulus = {p}')
t.close()

t = remote(host,port)
P1,P2 = find_points(t)
t.close()

F = GF(p)
E,a,b = recover_parameters(P1,P2)


FLAG = False
while not FLAG:
    t = remote(host,port)
    P = E.random_point()
    EP = P 

    x = P.xy()[0]

    t.sendlineafter(b'> ', b'1')
    t.recvline()
    t.sendlineafter(b'x : ', str(x).encode())
    res = t.recvline().decode().strip()

    assert 'Point confirmed on curve' in res
    P = list(map(ZZ,eval(res)[1:]))
    P = E(P)

    t.sendlineafter(b'> ', b'2')
    t.recvline()

    response = t.recvline().decode().strip()
    EP = list(map(ZZ,eval(response)[1:]))
    EP = E(EP)

    seed = SmartAttack(P,EP,p)
    assert P*seed == EP

    seed_roots = get_original_seed_roots(seed)

    if len(seed_roots) == 1:
        prng = PRNG(p,int(a),int(b))
        prng.seed = int(seed_roots[0])
        seed,enc_seed = prng.rotate()
        P = P * seed
        seed,enc_seed = prng.rotate()
        P = P * seed

        x,y = P.xy()

        t.sendlineafter(b'> ', b'3')
        t.recvline()
        t.sendlineafter(b'x: ', str(x).encode())
        t.sendlineafter(b'y: ', str(y).encode())

        response = t.recvline().decode().strip()

        print(response)
        FLAG = True
        #You have confirmed the location. However, It's dangerous to go alone. Take this:  HTB{th1s_4tt4ck_w4s_r3411y___SM4RT!}

    else:
        t.close()