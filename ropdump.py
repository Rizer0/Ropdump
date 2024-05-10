import argparse
import os
import sys
import re
from pwn import *

context.log_level = 'error'
print('''
 ____   ___  ____  ____  _   _ __  __ ____  
|  _ \ / _ \|  _ \|  _ \| | | |  \/  |  _ \ 
| |_) | | | | |_) | | | | | | | |\/| | |_) |
|  _ <| |_| |  __/| |_| | |_| | |  | |  __/ 
|_| \_\ ___/|_|   |____/ \___/|_|  |_|_|    
By @Nullbyte0x\n''')


def check_buffer_overflow(file_path):
    with open(file_path, 'rb') as f:
        binary_content = f.read()

    vulnerable_functions = {
        b'strcpy': 'strcpy',
        b'strcat': 'strcat',
        b'gets': 'gets',
        b'fscanf': 'fscanf',
        b'scanf': 'scanf',
    }

    found_vulnerabilities = []

    for func, func_name in vulnerable_functions.items():
        indices = [m.start() for m in re.finditer(func, binary_content)]
        for idx in indices:
            start_idx = max(0, idx - 20)
            end_idx = min(len(binary_content), idx + 20)
            context = binary_content[start_idx:end_idx].decode(errors='ignore')
            found_vulnerabilities.append((func_name, idx, context))

    if found_vulnerabilities:
        print("\033[31mPotential Buffer Overflow Vulnerabilities Detected:\033[0m")
        for func_name, idx, context in found_vulnerabilities:
            print(f"  \033[33mFunction:\033[0m {func_name}, \033[33mOffset:\033[0m {idx}")
            print(f"  \033[33mContext:\033[0m {context}")


def check_memory_leaks(file_path):
    with open(file_path, 'rb') as f:
        binary_content = f.read()

    memory_allocation_functions = {
        b'malloc': 'malloc',
        b'calloc': 'calloc',
        b'realloc': 'realloc',
        b'free': 'free',
    }

    found_memory_leaks = []

    for func, func_name in memory_allocation_functions.items():
        indices = [m.start() for m in re.finditer(func, binary_content)]
        for idx in indices:
            start_idx = max(0, idx - 20)
            end_idx = min(len(binary_content), idx + 20)
            context = binary_content[start_idx:end_idx].decode(errors='ignore')
            found_memory_leaks.append((func_name, idx, context))

    if found_memory_leaks:
        print("\033[31mPotential Memory Leak Vulnerabilities Detected:\033[0m")
        for func_name, idx, context in found_memory_leaks:
            print(f"  \033[33mFunction:\033[0m {func_name}, \033[33mOffset:\033[0m {idx}")
            print(f"  \033[33mContext:\033[0m {context}")


def disassemble_binary(file_path, search_string=None, print_functions=False):
    try:
        binary = ELF(file_path)
    except Exception as e:
        print(f"Error: {e}")
        return
    arch = binary.arch

    print("\n\033[1mBinary Information:\033[0m")
    print(f"  \033[32mArch:\033[0m {arch}")
    print(f"  \033[32mEntry Point:\033[0m {hex(binary.entry)}")
    print(f"  \033[32mRELRO:\033[0m {binary.relro}")
    print(f"  \033[32mStack:\033[0m {binary.canary}")
    print(f"  \033[32mNX:\033[0m {binary.nx}")
    print(f"  \033[32mPIE:\033[0m {binary.pie}")
    print(f"  \033[32mLibc used:\033[0m {binary.libc.path}")

    nx = str(binary.nx)

    with open(file_path, 'rb') as f:
        binary_content = f.read()
        disassembly = disasm(binary_content, arch=arch, vma=binary.address)
        instructions = disassembly.split('\n')
        rop_addresses = set()

        if print_functions:
            print("\n\033[1mFunctions:\033[0m")
            ignored_functions = {'printf', 'gets', '_IO_stdin_used', '_IO_stdin_getc', '_IO_stdout_used',
                                 '_IO_file_doallocate', '_IO_file_attach', '_DYNAMIC', 'libc', '__', '_GLOBAL_',
                                 'stdout', 'stderr', 'stdin', '_ITM_', 'plt.', 'got.', 'register_tm'}
            for symbol, address in binary.symbols.items():
                if not any(ignore_func in symbol for ignore_func in ignored_functions):
                    print(f"  \033[33m{symbol}\033[0m : {hex(address)}")

        print("\n\033[1mPotential ROP gadgets:\033[0m")
        print("  Gadget   :  Address:\t   Hex representation:\t Instruction:")
        if search_string:
            search_words = search_string.split()
            for idx, instruction in enumerate(instructions):
                addr_idx = instruction.find(":")
                if addr_idx != -1: 
                    hex_address = instruction[:addr_idx].strip()
                    try:
                        gadget_address = int(hex_address, 16)
                        if all(word in instruction for word in search_words):
                            if gadget_address not in rop_addresses:
                                rop_addresses.add(gadget_address)
                                print(f"  \033[33m0x{gadget_address:x}:\033[31m {instruction}")
                                reg = instruction.split(":")[0]
                                fmt = "0x"+reg.strip()
                                if binary.arch == 'i386':
                                    print(f"  \033[33mFormatted:\033[0m {p32(int(fmt, 16))}")
                                    if nx == "None" or nx == "False":
                                        shellcode = asm(shellcraft.i386.linux.sh())
                                        print(f"  \033[33mShellcode:\033[0m{shellcode}")
                                elif binary.arch == 'amd64':
                                    print(f"  \033[33mFormatted:\033[0m {p64(int(fmt, 16))}")
                                    if nx == "None" or nx == "False":
                                        try:
                                            shellcode = asm(shellcraft.amd64.linux.sh())
                                            print(f"  \033[33mShellcode:\033[0m{shellcode}")
                                        except NameError:
                                            print("Couldn't make a shellcode!")
                    except ValueError:
                        continue
        else:
            for idx, instruction in enumerate(instructions):
                if 'ret' in instruction or 'jmp' in instruction or 'pop' in instruction or 'test' in instruction or 'mov' in instruction:
                    addr_idx = instruction.find(":")
                    if addr_idx != -1:
                        hex_address = instruction[:addr_idx].strip()
                        try:
                            gadget_address = int(hex_address, 16)
                            if gadget_address not in rop_addresses:
                                rop_addresses.add(gadget_address)
                                print(f"  \033[33m0x{gadget_address:x}:\033[31m {instruction}")
                        except ValueError:
                            continue


def main():
    sys.stderr = open(os.devnull, 'w')

    parser = argparse.ArgumentParser(description="Disassemble binary and find potential ROP gadgets")
    parser.add_argument("binary", help="Path to the binary file")
    parser.add_argument("-s", "--search", help="Search string")
    parser.add_argument("-f", "--functions", action="store_true", help="Print function names and addresses")
    args = parser.parse_args()

    check_buffer_overflow(args.binary)
    check_memory_leaks(args.binary)
    disassemble_binary(args.binary, args.search, args.functions)

if __name__ == "__main__":
    main()
