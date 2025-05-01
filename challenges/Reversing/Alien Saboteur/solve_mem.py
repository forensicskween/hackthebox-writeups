import operator
from pwn import xor

OPCODES = {
    0x00: 'add',
    0x01: 'addi',
    0x02: 'sub',
    0x03: 'subi',
    0x04: 'mul',
    0x05: 'muli',
    0x06: 'div',
    0x07: 'cmp',
    0x08: 'jmp',
    0x09: 'inv',
    0x0A: 'push',
    0x0B: 'pop',
    0x0C: 'mov',
    0x0D: 'nop',
    0x0E: 'exit',
    0x0F: 'print',
    0x10: 'putc',
    0x11: 'je',
    0x12: 'jne',
    0x13: 'jle',
    0x14: 'jge',
    0x15: 'xor',
    0x16: 'store',
    0x17: 'load',
    0x18: 'input'
}

def u16(b):
    return int.from_bytes(b[:2], 'little')

def u32(b):
    return int.from_bytes(b[:4], 'little')


from struct import unpack

OPCODES = {0: 'add', 1: 'addi', 2: 'sub', 3: 'subi', 4: 'mul', 5: 'muli', 6: 'div', 7: 'cmp', 8: 'jmp', 9: 'inv', 10: 'push', 11: 'pop', 12: 'mov', 13: 'nop', 14: 'exit', 15: 'print', 16: 'putc', 17: 'je', 18: 'jne', 19: 'jle', 20: 'jge', 21: 'xor', 22: 'store', 23: 'load', 24: 'input'}

def u16(b):
    return int.from_bytes(b[:2], 'little')

def u32(b):
    return int.from_bytes(b[:4], 'little')

def disassemble(bytecode,verbose=False):
    ip = 0
    outputs = []
    while ip + 6 <= len(bytecode):
        chunk = bytecode[ip:ip+6]
        opcode = chunk[0]
        mnemonic = OPCODES.get(opcode, f'unk_{opcode:02x}')
        if verbose:
            print(f"{ip:04x}:", end=' ')

        if mnemonic in {'add', 'sub', 'mul', 'div', 'xor'}:
            if verbose:
                print(f"{mnemonic} r{chunk[1]}, r{chunk[2]}, r{chunk[3]}")
            outputs.append((mnemonic,chunk[1],chunk[2],chunk[3]))
        elif mnemonic in {'addi', 'subi', 'muli'}:
            if verbose:
                print(f"{mnemonic} r{chunk[1]}, r{chunk[2]}, {chunk[3]}")
            outputs.append((mnemonic,chunk[1],chunk[2],chunk[3]))
        elif mnemonic == 'mov':
            imm = u32(chunk[2:6])
            if verbose:
                print(f"mov r{chunk[1]}, {imm}")
            outputs.append((mnemonic,chunk[1],imm))
        elif mnemonic in {'push', 'pop', 'input', 'putc', 'print'}:
            if mnemonic == 'putc':
                if verbose:
                    print(f"{mnemonic} {chr(chunk[1])}")
                outputs.append((mnemonic,chr(chunk[1])))
            else:
                if verbose:
                    print(f"{mnemonic} r{chunk[1]}")
                outputs.append((mnemonic,chunk[1]))
        elif mnemonic in {'je', 'jne', 'jle', 'jge'}:
            r1 = chunk[1]
            r2 = chunk[2]
            target = u16(chunk[3:5]) * 6
            if verbose:
                print(f"{mnemonic} r{r1}, r{r2}, {target}")
            outputs.append((mnemonic,r1,r2,target))
        elif mnemonic == 'jmp':
            reg = chunk[2]
            if verbose:
                print(f"jmp r{reg}")
            outputs.append((mnemonic,reg))
        elif mnemonic == 'inv':
            sysno = chunk[1]
            argc = chunk[2]
            if verbose:
                print(f"inv {sysno} ({argc} args from stack)")
            outputs.append((mnemonic,sysno,argc))
        elif mnemonic == 'cmp':
            if verbose:
                print(f"cmp r{chunk[2]}, r{chunk[3]}")
            outputs.append((mnemonic,chunk[2],chunk[3]))
        elif mnemonic == 'load':
            if verbose:
                print(f"load r{chunk[1]}, r{chunk[2]}")
            outputs.append((mnemonic,chunk[1],chunk[2]))
        elif mnemonic == 'store':
            if verbose:
                print(f"store r{chunk[1]}, r{chunk[2]}")
            outputs.append((mnemonic,chunk[1],chunk[2]))
        elif mnemonic in {'nop', 'exit'}:
            if verbose:
                print(mnemonic)
            outputs.append((mnemonic,-1))
        else:
            outputs.append(('db',chunk))
            if verbose:
                print(f"db {chunk.hex()}")

        ip += 6
    return outputs


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


def reassemble_strings_and_bytes(outputs):
    output_items = []
    i = 0
    while i < len(outputs):
        opcode = outputs[i][0]
        if opcode in ('putc', 'db'):  # <-- check both putc and db
            start_i = i
            outstring = '' if opcode == 'putc' else b''
            while i < len(outputs) and outputs[i][0] in ('putc', 'db'):
                outstring += outputs[i][1]
                i += 1
            output_items.append((start_i,(opcode, outstring)))
        elif outputs[i] == ('add', 0, 0, 0):
            i+=1
            continue
        else:
            output_items.append((i, outputs[i]))
            i += 1
    return output_items


def patch_memory(verbose):
    memory = bytearray(open('bin','rb').read()[3:])
    outputs = disassemble(memory.rstrip(bytes(1))+bytes(4),verbose)
    outputs = reassemble_strings_and_bytes(outputs)
    if verbose:
        for v in outputs:
            print(v)


    print('[Main Vessel Terminal]\n< Enter keycode \n> ')
    part_1 = xor(memory[4100:4100+17], bytes([169]))
    print(f'Expected input -> {part_1.decode()}')

    registers = {}
    registers[30] = 119
    registers[30] = registers[30] * 6  # r30 = 714
    registers[28] = 0
    registers[29] = 1500
    registers[27] = 69

    while registers[28] < registers[29]:
        registers[25] = memory[registers[30]]       # load memory[r30]
        registers[25] = operator.xor(registers[27], registers[25])  # xor
        memory[registers[30]] = registers[25]       # store back
        registers[30] += 1                          # addi r30, 1
        registers[28] += 1    

    patched_output = [x for x in reassemble_strings_and_bytes(disassemble(memory,verbose)) if ('add', 0, 0, 0) not in x]
    if verbose:
        print("Patched Memory :")
        for v in patched_output:
            if v[1][0] == 'db': #'dead'
                print('dead')
                break
            print(v)
    

    final_secret = memory[4700:4700+36]
    perm_table = memory[4500:4500+36]
    xor_key = memory[4600:4600+36]
    flag = unscramble_and_unxor(final_secret, perm_table, xor_key)
    
    print('< Enter secret phrase\n> ')
    print(f'Expected input -> {flag.decode()}')

patch_memory(False)




