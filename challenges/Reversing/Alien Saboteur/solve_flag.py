from pwn import xor

def unscramble_and_unxor(expected, permutation_table, xor_key):
    user_input = bytearray(expected)  
    for outer in reversed(range(36)): 
        # UNXOR
        user_input = bytearray(xor(user_input, xor_key[outer]))
        # Unscramble (reverse swaps) and reverse rder of swaps!
        for i in reversed(range(36)):
            scramble_offset = permutation_table[i]
            scramble_address = scramble_offset
            user_input[i], user_input[scramble_address] = user_input[scramble_address], user_input[i]
    return user_input

def get_flag():
    with open('bin','rb') as infile:
        data = infile.read()

    data = data[3:]
    final_secret = data[4700:4700+36]
    perm_table = data[4500:4500+36]
    xor_key = data[4600:4600+36]
    flag = unscramble_and_unxor(final_secret, perm_table, xor_key)
    print(flag.decode())

if __name__ == """__main__""":
    get_flag()