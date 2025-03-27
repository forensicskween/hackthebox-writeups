# 🔐 Crypto Challenge

## 🏷️ Name: [AESWCM](https://app.hackthebox.com/challenges/437)

## 🔥 Difficulty: Medium

## 🎯 Points: 0

## ⏳ Status: 🟥 Retired

## 📜 Challenge Description: 
> Few people on this planet studied wandlore. It was known that the wand selects the wizard, but a good wand seller should be able to guess it with at most 3 suggestions. During the 190th Great Wizard Examination, the last question was created by Olivender, the greatest wand seller of all time. It was considered one of the most difficult questions of the last decade. Can you solve it?

## 📂 Provided Files:
- **Filename:** `AESWCM.zip`

- **SHA-256 Hash:** `8d3969cdedabf3f36420d7d96aca00ec989e1954783624c581c1be5afcb7797b`

# 🚀 Methodology
### 🔎 1️⃣ Understanding the Cryptosystem

The given cryptosystem is a custom AES encryption scheme where we can choose three plaintexts. Each plaintext is concatenated with a static prefix:

```
"Property: " + chosen_plaintext
```

This combined message is then padded using **PKCS7** but only if its length is not already a multiple of 16 bytes. The lack of mandatory padding introduces an opportunity to control message block alignment.

The encryption process follows a **modified CBC mode** but with a twist:

1. The **first block** is encrypted using **AES-ECB** after being XORed with the **IV**.
2. The next block is XORed with the **previous ciphertext block** before being encrypted.
3. The process repeats for subsequent blocks, using a rolling IV computed as:
   ```
   enc_block_1 = ECB(block_1 XOR IV)
   new_IV = block_1 XOR enc_block_1
   enc_block_2 = ECB(block_2 XOR new_IV)
   ```

After encryption, the ciphertext blocks are **randomly shuffled**, and the tag is computed by XORing all shuffled blocks together:

```
final_tag = shuffled_blocks[0] XOR shuffled_blocks[1] XOR ... XOR shuffled_blocks[n]
```

The **goal** of the attack is to **find a collision** in these tags, which triggers a flag leak.

---

### ⚡ 2️⃣ Identifying Vulnerabilities

#### 🛑 1. Random Shuffle is Useless

Since the **final tag is just the XOR of all blocks**, shuffling does not impact the outcome. XOR is **commutative** (`A ⊕ B = B ⊕ A`), so reordering does not change the result.

#### 🛑 2. Padding Weakness

The padding is only applied **if the message length is not a multiple of 16 bytes**. This means we can carefully craft messages that do not require padding, allowing precise block control.

#### 🛑 3. Ciphertext Manipulation & IV Reset

We can force the encryption process into a predictable cycle, leading to a **ciphertext reset** that lets us forge a valid tag. Specifically:

- By ensuring the **first block of every message is the same**, we can align the internal IVs across different messages.
- Constructing specific plaintexts allows us to manipulate the internal state, eventually forcing the system to repeat previous ciphertext values.

---

### 🔨 3️⃣ Exploiting the Weakness

To construct a tag collision, we:

1. **Craft two controlled plaintexts**:

   ```
   message_1 = b"Property: " + b"A" * 16
   message_2 = b"Property: " + b"B" * 16
   ```

2. **Encrypt both messages** and obtain their respective tags:

   ```
   T1 = oracle(message_1.hex())
   T2 = oracle(message_2.hex())
   ```

3. **Find the difference (XOR) between `T1` and `b'Property: ' + bytes(6)`**:

   ```
   forge = xor(bytes.fromhex(T1), b'Property: ' + bytes(6))
   ```

4. **Create a forged message** by appending the manipulated block:

   ```
   forged_message = (message_1 + forge + b"B" * 16).hex()
   ```

5. **Send the forged message** to obtain `T3`, which will match `T2`, triggering the flag leak:

   ```
   T3 = oracle(forged_message)
   ```

---

### 📌 Why the Forged Tag Works

We analyze why this approach successfully manipulates the cryptosystem:

1. The **first block of **``** and **``** is identical**, ensuring they produce the same first encrypted block.
2. The tag computation relies on **XORing all shuffled ciphertext blocks**, which means if we can force two messages to have identical block-wise XOR results, we can generate a collision.
3. **Ciphertext Reset via IV Manipulation**:
   - By appending `forge = xor(T1, M1[0])` to `message_1`, we create a new message where the encryption process resets.
   - This ensures that the encryption produces **the same second ciphertext block** as `message_2`.
   - As a result, when computing the tag, the second blocks in both messages cancel out, leading to `T3 = T2`.
4. The system **compares only tags**, so if we create a collision, it assumes the messages are identical and reveals the flag.

Thus, **by carefully controlling block alignments and exploiting the deterministic nature of AES-ECB and XOR, we successfully force a tag collision**.

---

### 🔑 4️⃣ Recovering the Flag

By following the exploitation steps above, we can forge a tag collision and extract the flag.

- The attack works because the encryption process allows **resetting the IV** to a known state, effectively repeating previous ciphertext values.
- XORing strategically chosen messages forces a deterministic tag collision.

This highlights why **custom cryptosystems should not be trusted**, as even seemingly minor weaknesses (like padding inconsistencies and shuffling-based authentication) can lead to complete breaks.


# 🏁 Solution & Commands

```python

from pwn import remote, xor


message_1 = bytes(6) + b'A'*16
message_2 = bytes(6) + b'B'*16

conn = remote('94.237.51.23','35415')
conn.recvuntil("What properties should your magic wand have?")

conn.sendlineafter(b'Property: ',message_1.hex().encode())
tag_1 = bytes.fromhex(conn.recvline().decode().strip())


conn.sendlineafter(b'Property: ',message_2.hex().encode())
tag_2 = bytes.fromhex(conn.recvline().decode().strip())

forge =  xor(tag_1,b'Property: '+bytes(6))
forged_message = (message_1 + forge + message_2[-16:]).hex()
conn.sendlineafter(b'Property: ',forged_message.encode())
tag_3 = bytes.fromhex(conn.recvline().decode().strip())

if tag_3 == tag_2:
    flag = conn.recvline().decode().strip()
    print(flag)
    #
    
```

**🚩 Final Flag:** `HTB{AES_cu570m_m0d35_4nd_hm4cs_423_fun}`

