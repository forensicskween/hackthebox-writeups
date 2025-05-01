from ctypes import *
import operator
import os

disassembly = False

putc_buffer = []
input_buffer = []

class VMStruct(Structure):
    _fields_ = [
        ('field0', c_int32),                 # offset 0x00
        ('halt_flag', c_uint8),              # offset 0x04
        ('padding1', c_uint8 * 3),           # fill 4 bytes total
        ('field2_to_33', c_uint8 * 0x80),    # offset 0x08 - 0x88 (128 bytes)
        ('padding2', c_uint8 * (0xA0 - 0x88)),  # pad to offset 0xA0
        ('field0x28', c_int32),              # offset 0xA0
        ('padding3', c_uint8 * (0x240 - 0xA4)), # pad to offset 0x240
        ('program_memory', POINTER(c_uint8)),  # *(result + 0x90)
        ('register_memory', POINTER(c_int32)),  # *(result + 0x98)
        ('cmp_flag', c_uint8),          # offset 0x88 (1 byte)
        ('pad_cmp', c_uint8 * (0xA0 - 0x89)),  # padding to reach next field

    ]

def fake_syscall(sys_num, args):
    if sys_num == 101:
        if disassembly:
            print('SYSCALL --> ptrace(PTRACE_TRACEME, 0, NULL, NULL)')
        return 0 




def vm_add(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    # Fetch operand register indices from program memory
    dst = prog[pc + 1]
    src1 = prog[pc + 2]
    src2 = prog[pc + 3]

    if disassembly:
        print(
        f"[{vm.contents.field0:04}] vm_add: "
        f"reg[{dst}] = reg[{src1}] + reg[{src2}] -> "
        f"{regs[dst]} = {regs[src1]} + {regs[src2]}"
        )
    
    # Compute and store the result
    regs[dst] = regs[src1] + regs[src2]

    # Increment program counter by 6
    vm.contents.field0 += 6

    return vm


def vm_putc(vm: POINTER(VMStruct)):
    global putc_buffer
    pc = vm.contents.field0
    prog = vm.contents.program_memory

    # Get the byte to print
    byte_val = prog[pc + 1]
    char = chr(byte_val)

    # Disassembly trace
    #if disassembly:
        #print(f"[{pc:04}] vm_putc: print char '{char}' (0x{byte_val:02x})")

    # Add to output buffer
    putc_buffer.append(char)

    # Auto-flush on newline
    if char == '\n':
        print(f"[{pc:04}] vm_putc:")
        print(''.join(putc_buffer), end='')  # print line without extra newline
        putc_buffer.clear()

    vm.contents.field0 += 6
    return vm


def vm_nop(vm: POINTER(VMStruct)):
    vm.contents.field0 += 6  # advance PC
    return vm


def vm_input(vm: POINTER(VMStruct)):
    global input_buffer
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    # If input buffer is empty, prompt once and fill it
    if not input_buffer:
        line = input(f"Asking for Input !! expects {regs[29]} chars \n> ")
        input_buffer = list(line + "\n")  # simulate pressing Enter

    # Pop the next character
    char_val = ord(input_buffer.pop(0))

    reg_idx = prog[pc + 1]
    if disassembly:
        print(f"[{pc:04}] vm_input: reg[{reg_idx}] = input() -> {char_val}")
    regs[reg_idx] = char_val
    vm.contents.field0 += 6
    return vm


def vm_store(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    # Fetch register indices from program memory
    addr_reg_idx = prog[pc + 1]
    val_reg_idx = prog[pc + 2]

    # Get the target memory address from addr_reg
    address = regs[addr_reg_idx]

    # Get the value from val_reg
    value = regs[val_reg_idx] & 0xFF  # store only 1 byte

    # Store value in program memory at computed address
    prog[address] = value
    if disassembly:
        print(f"[{pc:04}] vm_store: memory[reg[{addr_reg_idx}]] = reg[{val_reg_idx}] -> prog[{address}] = {value}")

    # Advance program counter
    vm.contents.field0 += 6

    return vm


def vm_load(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    # Fetch register indices
    dest_reg_idx = prog[pc + 1]
    addr_reg_idx = prog[pc + 2]

    # Get address from addr_reg
    address = regs[addr_reg_idx]

    # Load byte from program memory at address
    byte_val = prog[address]

    # Store into destination register
    regs[dest_reg_idx] = byte_val
    if disassembly:
        print(f"[{pc:04}] vm_load: reg[{dest_reg_idx}] = memory[reg[{addr_reg_idx}]] -> {byte_val}")

    # Advance PC
    vm.contents.field0 += 6

    return vm

def vm_xor(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    # Fetch register indices from bytecode
    dst = prog[pc + 1]
    src1 = prog[pc + 2]
    src2 = prog[pc + 3]

    # XOR the two source registers and store the result
    if disassembly:
        print(f"[{pc:04}] vm_xor: reg[{dst}] = reg[{src1}] ^ reg[{src2}] -> {regs[dst]} = {regs[src1]} ^ {regs[src2]} = {operator.xor(regs[src1],regs[src2])} ")

    regs[dst] = operator.xor(regs[src1],regs[src2])
    # Advance program counter
    vm.contents.field0 += 6

    return vm

def vm_je(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    # Get operand register indices
    reg1 = prog[pc + 1]
    reg2 = prog[pc + 2]


    # Compare values in the registers
    if regs[reg1] == regs[reg2]:
        # Read 2-byte jump offset from PC+3 and PC+4 (little-endian)
        jump_target = prog[pc + 3] | (prog[pc + 4] << 8)  # u16
        vm.contents.field0 = jump_target * 6  # each instruction is 6 bytes
        if disassembly:
            print(f"[{pc:04}] vm_je:  reg[{reg1}]({regs[reg1]}) == reg[{reg2}]({regs[reg2]});  -> jump to {jump_target * 6}")

    else:
        # Just move to the next instruction
        vm.contents.field0 += 6
        if disassembly:
            print(f"[{pc:04}] vm_je: reg[{reg1}]({regs[reg1]}) != reg[{reg2}]({regs[reg2]}) -> No Jump")


    return vm


def vm_jne(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    # Fetch operand register indices
    reg1 = prog[pc + 1]
    reg2 = prog[pc + 2]

    if disassembly:
        print(f"[{pc:04}] vm_jne: if reg[{reg1}] != reg[{reg2}] -> jump to {jump_target * 6}")

    if regs[reg1] == regs[reg2]:
        # No jump — advance to next instruction
        vm.contents.field0 += 6
    else:
        # Jump to instruction index * 6
        jump_target = prog[pc + 3] | (prog[pc + 4] << 8)  # u16
        vm.contents.field0 = jump_target * 6

    return vm

def vm_jle(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    reg1 = prog[pc + 1]
    reg2 = prog[pc + 2]

    val1 = regs[reg1]
    val2 = regs[reg2]

    if val1 > val2:
        vm.contents.field0 += 6  # no jump
        if disassembly:
            print(f"[{pc:04}] vm_jle: reg[{reg1}]({val1}) NOT <= reg[{reg2}]({val2}) -> No Jump")
    else:
        jump_target = prog[pc + 3] | (prog[pc + 4] << 8)  # u16
        vm.contents.field0 = jump_target * 6
        if disassembly:
            print(f"[{pc:04}] vm_jle: if reg[{reg1}]({val1}) <= reg[{reg2}]({val2}) -> jump to {jump_target * 6}")

    return vm


def vm_jge(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    reg1 = prog[pc + 1]
    reg2 = prog[pc + 2]

    val1 = regs[reg1]
    val2 = regs[reg2]

    if disassembly:
        print(f"[{pc:04}] vm_jge: if reg[{reg1}] >= reg[{reg2}] -> jump to {jump_target * 6}")

    if val1 < val2:
        vm.contents.field0 += 6  # no jump
    else:
        jump_target = prog[pc + 3] | (prog[pc + 4] << 8)  # u16
        vm.contents.field0 = jump_target * 6

    return vm


def vm_print(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    reg_idx = prog[pc + 1]
    value = regs[reg_idx]
    if disassembly:
        print(f"[{pc:04}] vm_print: reg[{reg_idx}] = 0x{regs[reg_idx]:x}")

    print(f"PRINT 0x{value:x}")

    vm.contents.field0 += 6
    return vm


def vm_addi(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    dst = prog[pc + 1]       # destination register index
    src = prog[pc + 2]        # source register index
    imm = prog[pc + 3]        # immediate byte (unsigned)
    if disassembly:
        print(f"[{pc:04}] vm_addi: reg[{dst}] = reg[{src}] + {imm} -> {regs[dst]} = {regs[src]} + {imm}")

    regs[dst] = regs[src] + imm

    vm.contents.field0 += 6
    return vm


def vm_sub(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    dst = prog[pc + 1]
    src1 = prog[pc + 2]
    src2 = prog[pc + 3]
    if disassembly:
        print(f"[{pc:04}] vm_sub: reg[{dst}] = reg[{src1}] - reg[{src2}] -> {regs[dst]} = {regs[src1]} - {regs[src2]}")


    regs[dst] = regs[src1] - regs[src2]

    vm.contents.field0 += 6
    return vm

def vm_subi(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    dst = prog[pc + 1]
    src = prog[pc + 2]
    imm = prog[pc + 3]
    if disassembly:
        print(f"[{pc:04}] vm_subi: reg[{dst}] = reg[{src}] - {imm} -> {regs[dst]} = {regs[src]} - {imm}")

    regs[dst] = regs[src] - imm

    vm.contents.field0 += 6
    return vm


def vm_mul(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    dst = prog[pc + 1]
    src1 = prog[pc + 2]
    src2 = prog[pc + 3]
    if disassembly:
        print(f"[{pc:04}] vm_mul: reg[{dst}] = reg[{src1}] * reg[{src2}] -> {regs[dst]} = {regs[src1]} * {regs[src2]}")


    regs[dst] = regs[src1] * regs[src2]

    vm.contents.field0 += 6
    return vm


def vm_muli(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    dst = prog[pc + 1]
    src = prog[pc + 2]
    imm = prog[pc + 3]
    if disassembly:
        print(f"[{pc:04}] vm_muli: reg[{dst}] = reg[{src}] * {imm} -> {regs[dst]} = {regs[src]} * {imm}")

    regs[dst] = regs[src] * imm

    vm.contents.field0 += 6
    return vm


def vm_cmp(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    reg1 = prog[pc + 2]
    reg2 = prog[pc + 3]

    if regs[reg1] == regs[reg2]:
        vm.contents.cmp_flag = 1
    else:
        vm.contents.cmp_flag = 0

    if disassembly:
        print(f"[{pc:04}] vm_cmp: reg[{reg1}] == reg[{reg2}] -> {regs[reg1]} == {regs[reg2]} -> flag = {vm.contents.cmp_flag}")

    vm.contents.field0 += 6
    return vm

def vm_div(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    dst = prog[pc + 1]
    src1 = prog[pc + 2]
    src2 = prog[pc + 3]

    divisor = regs[src2]
    if divisor == 0:
        print("Division by zero")
        exit(1)
    if disassembly:
        print(f"[{pc:04}] vm_div: reg[{dst}] = reg[{src1}] // reg[{src2}] -> {regs[dst]} = {regs[src1]} // {regs[src2]}")

    regs[dst] = regs[src1] // divisor

    vm.contents.field0 += 6
    return vm


def vm_inv(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    sysno = prog[pc + 1]
    arg_count = prog[pc + 2]

    stack_ptr = regs[40]  # Register 40 = stack pointer
    stack = regs

    def pop():
        nonlocal stack_ptr
        stack_ptr -= 1
        return stack[stack_ptr]

    arg1 = pop() if arg_count >= 1 else 0
    arg2 = pop() if arg_count >= 2 else 0
    arg3 = pop() if arg_count >= 3 else 0


    # Fake syscall (real one only works on Linux and depends on context)
    try:
        result = fake_syscall(sysno, (arg1, arg2, arg3))
    except Exception:
        result = -1  # Simulate syscall failure

    if disassembly:
        print(f"[{pc:04}] vm_inv: syscall {sysno}({arg1}, {arg2}, {arg3}) -> {result}")

    regs[31] = result  # Store syscall result

    # Update the stack pointer in register 40
    regs[40] = stack_ptr

    vm.contents.field0 += 6
    return vm

def vm_jmp(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    reg = prog[pc + 2]
    offset = regs[reg]
    if disassembly:
        print(f"[{pc:04}] vm_jmp: jump +{offset} -> PC = {vm.contents.field0 + offset + 6}")

    vm.contents.field0 += offset
    vm.contents.field0 += 6
    return vm


def vm_exit(vm: POINTER(VMStruct)):
    pc = vm.contents.field0  # define pc before using it
    vm.contents.halt_flag = 1
    vm.contents.field0 += 6

    if disassembly:
        print(f"[{pc:04}] vm_exit: halt VM")

    return 0


def vm_push(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    reg = prog[pc + 1]
    val = regs[reg]

    stack_ptr = regs[40]
    stack = regs  # Same memory used

    stack[stack_ptr] = val
    regs[40] += 1  # increment stack pointer
    if disassembly:
        print(f"[{pc:04}] vm_push: push reg[{reg}] -> {val} (SP={stack_ptr})")


    vm.contents.field0 += 6
    return vm

def vm_pop(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    dest_reg = prog[pc + 1]

    stack_ptr = regs[40]
    if stack_ptr == 0:
        print("Stack underflow")
        exit(1)

    stack_ptr -= 1
    val = regs[stack_ptr]
    regs[dest_reg] = val
    regs[40] = stack_ptr  # update stack pointer
    if disassembly:
        print(f"[{pc:04}] vm_pop: reg[{dest_reg}] = pop() -> {val} (SP={stack_ptr})")

    vm.contents.field0 += 6
    return vm


def vm_mov(vm: POINTER(VMStruct)):
    pc = vm.contents.field0
    prog = vm.contents.program_memory
    regs = vm.contents.register_memory

    dest_reg = prog[pc + 1]

    # Read 4-byte little-endian immediate value
    imm = int.from_bytes(bytes(prog[pc + 2 : pc + 6]), 'little')
    if disassembly:
        print(f"[{pc:04}] vm_mov: reg[{dest_reg}] = 0x{imm:08x}")

    regs[dest_reg] = imm
    vm.contents.field0 += 6
    return vm





def vm_step(vm: POINTER(VMStruct)):
    pc = vm.contents.field0  # PC is at offset 0x00

    # Get opcode from program memory
    opcode = vm.contents.program_memory[pc]

    if opcode > 0x19:
        print("dead")
        exit(0)

    return original_ops[opcode](vm)



def vm_create(arg1: bytes, arg2: int) -> POINTER(VMStruct):
    # Allocate the main structure
    vm = pointer(VMStruct())

    # Equivalent to *result = 0
    vm.contents.field0 = 0

    # Equivalent to result[1].b = 0 (already 0 because zero-init)
    vm.contents.halt_flag = 0

    # Equivalent to result[0x28] = 0
    vm.contents.field0x28 = 0

    # field2_to_33 was already zero-initialized as an array

    # Allocate program memory (0x10000 bytes)
    program_mem = (c_uint8 * 0x10000)()
    memmove(program_mem, arg1[3:], arg2 - 3)
    vm.contents.program_memory = cast(program_mem, POINTER(c_uint8))

    # Allocate register/stack memory (2048 * 4 bytes)
    register_mem = (c_int32 * 0x200)()
    vm.contents.register_memory = cast(register_mem, POINTER(c_int32))

    return vm

original_ops = [vm_add, vm_addi, vm_sub, vm_subi, vm_mul, vm_muli, vm_div, vm_cmp, vm_jmp, vm_inv, vm_push, vm_pop, vm_mov, vm_nop, vm_exit, vm_print, vm_putc, vm_je, vm_jne, vm_jle, vm_jge, vm_xor, vm_store, vm_load, vm_input]

a1 = open('bin','rb').read()
a2 = len(a1)
vm = vm_create(a1, a2) 
disassembly = True
while vm.contents.halt_flag == 0:
   ret = vm_step(vm)

