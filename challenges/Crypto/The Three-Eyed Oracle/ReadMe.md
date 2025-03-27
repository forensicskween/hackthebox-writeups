# 🔐 Crypto Challenge

## 🏷️ Name: [The Three-Eyed Oracle](https://app.hackthebox.com/challenges/342)

## 🔥 Difficulty: Easy

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> Feeling very frustrated for getting excited about the AI and not thinking about the possibility of it malfunctioning, you blame the encryption of your brain. Feeling defeated and ashamed to have put Miyuki, who saved you, in danger, you slowly walk back to the lab. More determined than ever to find out what’s wrong with your brain, you start poking at one of its chips. This chip is linked to a decision-making algorithm based on human intuition. It seems to be encrypted… but some errors pop up when certain user data is entered. Is there a way to extract more information and fix the chip?

## 📂 Provided Files:
- **Filename:** `The_Three-Eyed_Oracle.zip`

- **SHA-256 Hash:** `f217821ad56e7628452047b9181cb5d31d868073e140ed5f556e2493d7845226`

# 🚀 Methodology

### 🔎 1️⃣ Understanding the Cryptosystem

This is an ECB Encryption Algorithm where the encryption is:

- an unknown prefix of 12 bytes
- chosen plaintext
- unknown secret (the flag)

The custom message is then padded with PKCS7.

### ⚡ 2️⃣ Identifying Vulnerabilities

The problem with ECB is that it can leak information about the plaintext.

Since there are no alterations to the message, like xor or whatever,

for example:
E1 = ECB('AAAAAAAAAAAAAAAA')
E2 = EBC('BBBBBBBBBBBBBBBB')
E3 = ECB('AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB')
E3[:16] == E1 and E3[16:] == E2


### 🔨 3️⃣ Exploiting the Weakness

We have an additional problem, the prefix and the suffix; but that can easily be manipulated if we position our chosen plaintext appropriately.

First of all, we can completely ignore the prefix by starting our plaintext with 4 bytes.

This means that our chosen plaintext attack starts at block 1.

pad_bytes = bytes(4)
to find the first letter of the flag, we do:

start = pad_bytes + bytes(15) + b'H' + bytes(15)


# 🏁 Solution & Commands

```python

import string
from pwn import remote

conn = remote('94.237.55.96','51484')
conn.recvuntil(b'Can you somehow extract the firmware and fix the chip?\n')


def oracle(message):
    conn.sendlineafter(b'> ',message.hex())
    result = conn.recvline().decode().strip()
    return blk(bytes.fromhex(result))

known_secret = b'HTB{'
for i in range(32):
    for s in string.printable.encode():
        position_x = (len(known_secret)//16)+1
        position_y = position_x + position_x
        temp_secret = (known_secret + bytes([s]))
        padding_len = (16 - len(temp_secret)%16)
        if padding_len == 16:
            padding_len = 0 
        start = pad_bytes +  bytes(padding_len) + temp_secret + bytes(padding_len)
        blocks = oracle(start)
        if blocks[position_x] == blocks[position_y]:
            known_secret = temp_secret
            print(known_secret.decode())
            break
    if known_secret.endswith(b'}'):
        break

```

**🚩 Final Flag:** `HTB{7h3_br0k3n_0r@c1e!!!}`

