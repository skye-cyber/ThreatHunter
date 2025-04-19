import capstone

# Sample x86_64 machine code with int3 and int1 instructions
# int3 is 0xCC and int1 is 0xF1 in machine code
machine_code = b'\x55\x48\x8b\x05\xb8\x13\x00\x00\xcc\x48\x8b\x10\xf1\xc3'

# Initialize the Capstone disassembler for x86_64 architecture
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# Disassemble the machine code
print("Disassembly:")
for i in md.disasm(machine_code, 0x1000):  # Assume code starts at address 0x1000
    print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

# Simulate malware anti-debugging behavior


def check_for_debugging():
    for i in md.disasm(machine_code, 0x1000):
        if i.mnemonic == 'int3':
            print(
                f"Debugger detected at address 0x{i.address:x} (int3 instruction)")
            return True
        if i.mnemonic == 'int1':
            print(
                f"Debugger detected at address 0x{i.address:x} (int1 instruction)")
            return True
    return False


# Check if debugging is detected
if check_for_debugging():
    print("Anti-debugging routine activated. Exiting.")
else:
    print("No debugger detected. Continuing execution.")

# Normal execution (for illustration purposes)


def normal_execution():
    print("Executing normally...")


normal_execution()
