# 🔐 Crypto Challenge

## 🏷️ Name: [Biased Heritage](https://app.hackthebox.com/challenges/481)

## 🔥 Difficulty: Hard

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> You emerge from the labyrinth to find a massive door blocking your path to the relic. It has the same authentication mechanism as the entrance, but it appears to be more sophisticated and challenging to crack. Can you devise a plan to breach the door and gain access to the relic?

## 📂 Provided Files:
- **Filename:** `Biased Heritage.zip`

- **SHA-256 Hash:** `8eb01fed68f675016a8b2eed58323d7ab056fb16d4e499093fdcf4639b343323`

# 🚀 Methodology
## 🔎 1️⃣ Understanding the Cryptosystem

### **Server Basics**  
We are given the values **$g, y, p$** and can interact with the server **three times**.  

We have two possible actions:  
1. **Request a signature** for a chosen message.  
2. **Verify a signature** for a given message.  

To obtain the **flag**, we must generate a valid Schnorr signature for:  

```
b'right hand'
```

However, the server enforces a **30-second time limit**, implying that the attack must be solvable in **$O(\log n)$ complexity**.  

---

### **SHA256 Schnorr Signature**  
Schnorr signatures are **efficient** and **secure**, relying on the hardness of the **Discrete Logarithm Problem (DLP)**.  

A standard Schnorr signing process consists of the following steps:  

#### **1️⃣ Compute Nonce $k$**  
To sign a message $m$, the signer selects a **random** ephemeral key $k$:  

$$k \xleftarrow{\$} \{1, \dots, q-1\}$$

This nonce **must be secret and unique** for each signature.  

#### **2️⃣ Compute Commitment $r$**  
The signer computes the **commitment value**:  

$$r = g^k \mod p \mod q$$

#### **3️⃣ Compute Challenge Hash $e$**  
The signer computes:  

$$e = H(\text{l2b}(r) \, || \, \text{msg}) \mod q$$

where $H(\cdot)$ is **SHA-256**.  

#### **4️⃣ Compute Signature Component $s$**  
The final signature component is:  

$$s = (k - x \cdot e) \mod q$$

where:
- $x$ is the **private key**.  
- $s$ represents the **masked nonce** incorporating the private key.  

#### **Final Signature Output**  
The signature consists of $(s, e)$

---

## ⚡ 2️⃣ Identifying Vulnerabilities  

The **critical flaw** in this implementation is that the nonce $k$ is **not random**, as indicated by the challenge name **"Biased Heritage"**. Instead of using a true random nonce, the signer **deterministically computes** $k$ as follows:

$$k = H(\text{msg} + \text{l2b}(x))$$

Expanding the hash function:

$$k = b2l(2 \cdot SHA256(msg + l2b(x)).digest()) \mod q$$

which simplifies to:

$$k = (\mathtt{m\_digest} \times 2^{256} + \mathtt{msg\_digest}) \mod q$$

Since $k$ is deterministic, we can model the problem as:

$$K_i = (k_i \times 2^{256} + k_i)$$

$$E_i = (K_i - d \cdot e_i) - s_i$$

Solving for $d$:

$$d = \frac{K_i - s_i}{e_i} \mod q$$

This allows us to **recover $k$** and ultimately extract the private key $x$.  

---

## 🔨 3️⃣ Exploiting the Weakness  

To solve for $k$, we generate **two equations** using two different message signatures:  

1. Request a signature for **"hello"**:  

$$K_1 = (k_1 \times 2^{256} + k_1)$$

$$E_1 = \frac{K_1 - s_1}{e_1}$$

2. Request a signature for **"hi"**:  

$$K_2 = (k_2 \times 2^{256} + k_2)$$

$$E_2 = \frac{K_2 - s_2}{e_2}$$

Since both equations share the **same private key** $d$, subtracting them gives:

$$D = E_1 - E_2$$

This results in a **Coppersmith small roots problem**, where we can solve for $k_1, k_2$ using polynomial root-finding techniques.  

Once $k_1$ and $k_2$ are recovered, we compute $d$ and **forge a valid signature for "right hand"**.  

---

## 🔑 4️⃣ Recovering the Flag  

1. Request two signatures:  

   - $(s_1, e_1) = \text{sign}("hello")$  
   - $(s_2, e_2) = \text{sign}("hi")$  

2. Construct the polynomial equation and apply **Coppersmith’s small roots method**.  

3. Recover $k_1, k_2$, solve for $d$, and sign **"right hand"** with the extracted private key.  

4. Submit the forged signature to retrieve the **flag**! 


# 🏁 Solution & Commands

```python

from pwn import remote
from server import SHA256chnorr
#coppersmith.small_roots is from defund github repository

sha256chnorr = SHA256chnorr()

host,port= '94.237.56.224','45766'

Poly.<k1,k2> = PolynomialRing(GF(sha256chnorr.q))
K1 = (k1*(2**256)+k1)
K2 = (k2*(2**256)+k2)


found = False

while not found:
    conn = remote(host,port)
    conn.recvuntil(b'y: ')
    y = int(conn.recvline().decode().strip())

    conn.sendlineafter(b'> ',b'S')
    conn.sendlineafter(b'Enter message> ',b'hello'.hex().encode())
    s1,e1 = eval(conn.recvline().decode().strip().split(': ')[1])

    conn.sendlineafter(b'> ',b'S')
    conn.sendlineafter(b'Enter message> ',b'hi'.hex().encode())
    s2,e2 = eval(conn.recvline().decode().strip().split(': ')[1])


    E1 = (K1-s1)/e1
    E2 = (K2 - s2)/e2
    D = E1-E2
    roots =  coppersmith.small_roots(D,(2**256,2**256),m=8,d=3)
    part_x = int(E1.subs(k1=roots[0][0]))

    if pow(sha256chnorr.g,part_x,sha256chnorr.p) == y:
        sha256chnorr.x = part_x
        s,e = sha256chnorr.sign(b'right hand')
        conn.sendlineafter(b'> ',b'V')
        conn.sendlineafter(b'Enter message> ',b'right hand'.hex().encode())
        conn.sendlineafter(b'Enter s> ',str(s).encode())
        conn.sendlineafter(b'Enter e> ',str(e).encode())
        conn.interactive()
        conn.close()
        found = True
    conn.close()


```

**🚩 Final Flag:** `HTB{unf027un4731y_7h3_n0nc3_1uck5_3n720py!!}`

