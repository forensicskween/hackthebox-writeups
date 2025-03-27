# 🔐 Crypto Challenge

## 🏷️ Name: [Converging Visions](https://app.hackthebox.com/challenges/482)

## 🔥 Difficulty: Hard

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> As you hold the relic in your hands, it prompts you to input a coordinate. The ancient scriptures you uncovered near the pharaoh's tomb reveal that the artifact is capable of transmitting the locations of vessels. The initial coordinate must be withi

## 📂 Provided Files:
- **Filename:** `Converging Visions.zip`

- **SHA-256 Hash:** `7a86b8230f9ef411fb80c5bb76923be78272631b4a1efcda7784351f545e8fda`

# 🚀 Methodology

---

### 🔎 1️⃣ Understanding the Cryptosystem


This challenge is based on **Elliptic Curve Cryptography (ECC)** with a twist:  
we’re **not given the curve parameters** 😭😭😭!

---

#### The ECC Setup

1. **Elliptic Curve (EC):**

   The `utils.py` file defines a standard elliptic curve class. However:
   - The parameters $p$, $a$, and $b$ are **unknown**.
   - We must recover these before doing anything else 😩.

2. **Pseudo-Random Number Generator (PRNG):**

   The PRNG is used to generate scalars for elliptic curve point multiplication. Its structure resembles a cubic Linear Congruential Generator (LCG):

   $$\text{seed}_{i+1} = (a \cdot \text{seed}_i^3 + b \cdot \text{seed}_i + \text{inc}) \bmod n$$
   
   
   $$\text{encseed}\_{i+1} = (\text{seed}_{i+1})^2 \bmod n$$

   The only known constant is:

   ```python
   inc = int.from_bytes(b'Coordinates lost in space', 'big')
   ```

   The modulus $n$ is a large number — a **composite** — which contains the prime $p$ used for the elliptic curve field.  However, since the outputs of the PRNG are only used to multiply Elliptic Curve points over GF(p); then it doesn't matter what the other factors are; because regardless it will always be reduced to modulo p. 

---
#### The Server Interface

The server provides **three options**:

---

##### Option 1: **Send a Point**

- You send a candidate $x$-coordinate.
- The server checks if $x < p$. If not, it replies:
  ```
  "Coordinate greater than curve modulus"
  ```
- If $x$ is in range, it tries to construct the EC point using:
  ```python
  P = E.get_point(x)  # Essentially equivalent to E.lift_x(x) in sage
  ```
- If successful, it stores:
  ```python
  EP = P
  ```
- Server responses:
  - X is bigger than p → `"Coordinate greater than curve modulus→"`
  - Not on curve → `"Point not on curve"`
  - Success → `("Point confirmed on curve", P.x, P.y)`

**This means we can brute-force or binary search for $p$** just by observing whether the server rejects our $x$.

---

##### Option 2: **Receive a New Point**

- The server generates the next PRNG value:

  $$\text{seed}, \text{encseed} = \text{PRNG.rotate()}$$

- Then it computes:

  $$P' = P \cdot \text{seed}$$
  $$EP' = EP \cdot \text{encseed}$$

- But the server **only returns** $EP'$. We never see $P'$.


---

##### Option 3: **Find True Point**

- You send your guess for $P' = (x, y)$.
- Internally, the server computes a new $P'$ as in Option 2.
- If your submitted point matches the server’s internal one, we get the flag.

**The Goal:** Successfully compute the next encrypted point $P'$ and send it back.

To do that, we need:

- The actual curve parameters $p$, $a$, $b$

- The current seed state of the PRNG

---



### ⚡ 2️⃣ Recovering Curve Parameters

---

#### Step 1: Recover the Field Prime $p$

- Because the server checks whether your submitted $x$ is greater than $p$, we can perform a **binary search** to discover $p$.

- Once the server sends:
  ```
  "Coordinate greater than curve modulus"
  ```

  we've found the modulus.

I used this writeup to write the code [cinsects.de on elliptic curves](https://cinsects.de/tag/elliptic-curves.html)


  ```python
    from pwn import remote 

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

    t = remote('94.237.52.195','41366')
    p = recover_modulus(t)
    print(F'Modulus = {p}')
    t.close()

  ```


   ```
   Modulus = 98807859381918657537428263421507671098277046895420042063839316200156326157051
   ```

---

#### Step 2: Recover the Curve Coefficients $a$, $b$

Now that we've found $p$, we need to find two valid points on the curve to find $a$ and $b$. Then:

1. Use Option 1 to get **two valid points** on the curve:

   $$P_1 = (x_1, y_1), \quad P_2 = (x_2, y_2)$$

2. Use the curve equation:

   $$y^2 \equiv x^3 + ax + b \pmod{p}$$

3. Plug in the known points into the equation and solve for \$a\$ and \$b\$.

We need to set the code to filter out values with y = 0 

  ```python
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

    (x1,y1),(x2,y2) = find_points(t)

  ```


Next, we can find the values of a and b: 

  ```python
    Poly.<a,b> = PolynomialRing(GF(p))

    p1 = (x1^3 + a*x1 + b) - y1^2
    p2 = (x2^3 + a*x2 + b) - y2^2

    a = (p1-p2).univariate_polynomial().roots()[0][0]
    b = p1.subs(a=a).univariate_polynomial().roots()[0][0]

    E = EllipticCurve(GF(p),[a,b])

    assert E(ZZ(x1),ZZ(y1))
    assert E(ZZ(x2),ZZ(y2))

    order = E.order()
    print(f'Order : {order}')
    
```

AND WE HAVE OUR VULNERABILITY

  ```
    Order : 98807859381918657537428263421507671098277046895420042063839316200156326157051
  ```

The order is the same as the prime, meaning

  ```python

    assert E.trace_of_frobenius() == 1

  ```

This means we can implement Smart's Attack to solve the Discrete Log Problem and recover the seeds. 

---

--- 
### ⚡ 2️⃣ Identifying Vulnerabilities


> The order of the elliptic curve is equal to the field size $p$ ($E(\mathbb{F}_p) = p$), so the **trace of Frobenius** is $t = 1$

**Smart's Attack** is a **discrete logarithm attack** against elliptic curves where the **order of the curve is equal to the field size**:

$E(\mathbb{F}_p) = p$

--- 

#### Why the attack works

For a prime $p$ and elliptic curve over $\mathbb{F}_p$, the number of points satisfies **Hasse’s theorem**:

$$E(\mathbb{F}_p) = p + 1 - t$$

where $t$ is the **trace of Frobenius**.

So if $E(\mathbb{F}_p) = p$, then:

$$p + 1 - t = p \Rightarrow t = 1$$


When $(\mathbb{F}_p) = p$, the curve is isomorphic (as a group) to **$\mathbb{F}_p^+$** — the additive group of the field. This collapses ECC security to solving **discrete logs in $\mathbb{F}_p$**, which is trivial.

**Given**:

- A base point $P$
- A target point $Q = kP$
- We want to solve for $k$

The **attack** works by:

1. **Mapping the curve to the additive group** of $\mathbb{F}_p$:
   There’s an **isomorphism** $\phi: E(\mathbb{F}_p) \to \mathbb{F}_p$ that preserves the group operation.

2. Computing:
   $$\phi(Q) = k \cdot \phi(P)$$
   in $\mathbb{F}_p$

3. Solving for $k$ via:
   $$k = \phi(Q) \cdot \phi(P)^{-1} \pmod{p}$$


### 🔨 3️⃣ Exploiting the Weakness

I found a clean and effective implementation of Smart’s attack in [this CTFTime writeup](https://ctftime.org/writeup/38441):

```python

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

```

You can test it like this:

```python
G = E.gens()[0]
k = randint(0, p - 1)
P = k * G
assert k == SmartAttack(G, P, p)
```


This gives us reliable recovery of \$k\$ from \$G\$ and \$P = kG\$, but we need to consider the tricky design of the server.

The server behavior includes this:

- You send a point \$P\$

- The server generates a seed \$seed\$ and computes:
  $$P \gets P \cdot k$$
  $$EP \gets EP \cdot k^2$$
  
- **You receive only \$EP\$**, not \$k\$

So: you must solve **\$k^2\$ from \$EP\$**, then reverse to get **\$k\$**

This means:

- You perform Smart’s attack to recover \$k^2\$ from \$EP\$
- Then take a square root mod \$p\$ to get \$k\$ (there are 2 candidates)
- Use both and test them


### 🔑 4️⃣ Recovering the Flag


With the Smart attack working, the flag recovery strategy is simple:

1. Send a known point \$P\$ to the server
2. Get back the encrypted point \$EP = EP \cdot k^2\$
3. Use Smart’s attack to recover \$k^2\$ from \$EP\$
4. Take square roots mod \$p\$ to get candidates for \$k\$
5. Compute \$P' = P \cdot k\$ (the server's expected \$P\$)
6. Recompute the new \$EP\$ with updated PRNG
7. Submit computed \$EP'\$ to get the flag 




```python



F = GF(p)

def get_original_seed_roots(seed):
    inc = 423298202838516040093965914645844180330692880951980532523877
    poly.<s> = PolynomialRing(F)
    fx = (a * pow(s, 3) + b * s + inc)^2
    fx = fx - seed
    return  [x[0] for x in fx.roots()]


t = remote('94.237.52.195','41366')
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

```


# 🏁 Solution & Commands

```python


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



t = remote('94.237.52.195','41366')
p = recover_modulus(t)
print(F'Modulus = {p}')
t.close()

t = remote('94.237.52.195','41366')
P1,P2 = find_points(t)
t.close()

F = GF(p)
E,a,b = recover_parameters(P1,P2)


FLAG = False
while not FLAG:
    t = remote('94.237.52.195','41366')
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

```

**🚩 Final Flag:** `HTB{th1s_4tt4ck_w4s_r3411y___SM4RT!}`

