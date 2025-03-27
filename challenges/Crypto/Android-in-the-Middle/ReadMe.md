# 🔐 Crypto Challenge

## 🏷️ Name: [Android-in-the-Middle](https://app.hackthebox.com/challenges/340)

## 🔥 Difficulty: Very Easy

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> Years have passed since Miyuki rescued you from the graveyard. When Virgil tells you that he needs your help with something he found there, desperate thoughts about your father and the disabilities you developed due to the disposal process come to mind. The device looks like an advanced GPS with AI capabilities. Riddled with questions about the past, you are pessimistic that you could be of any value. After hours of fiddling and observing the power traces of this strange device, you and Virgil manage to connect to the debugging interface and write an interpreter to control the signals. The protocol looks familiar to you. Your father always talked about implementing this scheme in devices for security reasons. Could it have been him?

## 📂 Provided Files:
- **Filename:** `Android in the Middle.zip`

- **SHA-256 Hash:** `26c18c39cc364451599672762ae589380cd3b6fa8e50e5cee08cbcd3c373f525`

# 🚀 Methodology

### 🔎 1️⃣ Understanding the Cryptosystem

This is a mix of DHKE and AES ECB cryptosystem.

The server gives us $g$ and $p$. 
It then calculates secret value $c$, and public key $C$: 

$$C = g^c \mod p$$

but never sends us the public key...

We must then provide a 'Public Key' to compute the shared secret.

$$S = M^c \mod p$$


The MD5 hash of the shared secret will be used to generate the AES key. 

This is a standard Diffie-Hellman shared secret calculation.


### ⚡ 2️⃣ Identifying Vulnerabilities

This challenge involves **Diffie-Hellman Key Exchange (DHKE)**, but it has a critical flaw. If an attacker sends `0`, `p`, `1`, or `p+1` as the public key, the shared secret becomes predictable due to **group theory and modular arithmetic**.


## 1. Diffie-Hellman Key Exchange Recap

In Diffie-Hellman, we work within the **multiplicative group of integers modulo $p$**:

$$\mathbb{Z}_p^* = \{ 1, 2, ..., p-1 \}$$

- The server generates a **private key** $c$.
- The **public key** is:

  $$C = g^c \mod p$$

- The client sends its **public key** $M$, and the server computes the **shared secret**:

  $$S = M^c \mod p$$

Since $p$ is a prime number, the group $\mathbb{Z}_p^*$ is well-structured for cryptographic operations. However, certain values of $M$ break this structure.

---

## 2. What Happens if You Send 0 or p?

If $M = 0$:

$$
S = 0^c \mod p = 0
$$

If $M = p$:

$$
S = p^c \mod p = 0
$$

Both cases result in a shared secret of **0**, which is easy to guess.

---

## 3. What Happens if You Send 1 or p+1?

If $M = 1$:

$$
S = 1^c \mod p = 1
$$

If $M = p+1$, since $p+1 \equiv 1 \mod p$:

$$
S = 1^c \mod p = 1
$$

These force the shared secret to **1**, which is also predictable.

---

## 4. Why Does This Happen? (Group Theory Perspective)

### **(a) Modular Arithmetic and the Multiplicative Group**
Diffie-Hellman operates in **$\mathbb{Z}_p^*$ (the set of integers modulo $p$, under multiplication)**. This group **excludes 0** because it has no multiplicative inverse.

- The generator $g$ is chosen to produce all elements in the group.
- The security relies on the **Discrete Log Problem**—but this problem assumes you're working within a proper group.

If an attacker **chooses values that are not valid group elements** (like `0` or `p`), the entire structure falls apart.

### **(b) Edge Cases from Number Theory**
1. **Zero is the absorbing element in multiplication**:
   $$0^c = 0$$

2. **One is the identity element**:
   $$1^c = 1$$

3. **Since $p \equiv 0 \mod p$ and $p+1 \equiv 1 \mod p$, the calculations simplify** and become predictable.

---

# 🏁 Solution & Commands

```python

from pwn import remote
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib

def encrypt(plaintext, shared_secret):
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    message = cipher.encrypt(plaintext)
    return message

encrypted_sequence = encrypt(b"Initialization Sequence - Code 0",1).hex().encode()

conn = remote(host,port)

conn.sendlineafter(b"Enter The Public Key of The Memory: ",b'1')
conn.sendlineafter(b"Enter The Encrypted Initialization Sequence: ",encrypted_sequence)

conn.recvline().decode().strip()
flag_message = conn.recv().decode().strip()
print(flag_message)

```

**🚩 Final Flag:** `HTB{7h15_15_cr3@t3d_by_Danb3er_@nd_h@s_c0pyr1gh7_1aws!_!}`

