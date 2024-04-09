import sys
# import subprocess
# from typing import Any
import hashlib
from elftools.elf.elffile import ELFFile
import logging
import logging.handlers

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)


def is_elf(binary_path):
    try:
        with open(binary_path, 'rb') as f:
            data = f.read(4)

        if data == b'\x7fELF':
            return True
        else:
            return False
    except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
        print(f'{e}')
        return False


def elfparser(input_file):
    try:
        # Open the input ELF file
        with open(input_file, "rb") as f:
            # Parse the ELF file
            elf_file = ELFFile(f)

            # Print the ELF file class
            print(
                "\033[34m__________________________BASIC INFO__________________________\033[0m")

            print(
                f"\tTarget Marchine word size: \033[32m{elf_file.elfclass}\033[0m")
            print(
                f"\tTarget machine's endianness: \033[32m{elf_file.little_endian}")

            # print(f'{elf_file.header}')
            print(
                "\033[34m__________________________HEADER INFO__________________________\033[0m")
            print(
                f"\tMagic number: \033[32m{elf_file.header.e_ident.EI_MAG}\033[0m")

            '''This indicates whether the file is a 32-bit  or 64-bit ELF
            ELFCLASS32=32-bit and ELFCLASS64=64-bit ELF file.'''
            print(
                f"\tFile Type(32 or 64 bits): \033[32m{elf_file.header.e_ident.EI_CLASS}\033[0m")

            '''ELFDATA2MSB - 2's complement, little-endian encoding for
            multi-byte data types while ELFDATA2LSB - indicate 2's complement,
            big-endian encoding.'''

            print(
                f"\tData Encoding: \033[32m{elf_file.header.e_ident.EI_DATA}\033[0m")
            # EV_CURRENT indicates that the file uses the most recent version\
            # of the ELF specification
            print(
                f"\tFile Version: \033[32m{elf_file.header.e_ident.EI_VERSION}\033[0m")
            # ABI for the target os, default for unix =ELFOSABI_SYSV, linux =ELFOSABI_LINUX
            print(
                f"\tTarget OS ABI: \033[32m{elf_file.header.e_ident.EI_OSABI}\033[0m")
            # ABI version number for the specified OS ABI default = 0
            print(
                f"\tTarget OS ABI Version: \033[32m{elf_file.header.e_ident.EI_ABIVERSION}\033[0m")

            # e_machine indicates the target instruction set architecture
            '''EM_386 - Intel 80386 architecture
            EM_AARCH64_BE - 64-bit little-endian AMD64 architecture
            EM_MIPS - MIPS R3000 architecture'''
            print(f"\n\tMachine: \033[32m{elf_file.header.e_machine}\033[0m")
            # Offset from file beginning to Program Header
            print(
                f"\tProgram Header Offset: \033[32m{elf_file.header.e_phoff}\033[0m")
            print(
                f"\tHeader Version: \033[32m{elf_file.header.e_version}\033[0m")
            # 0 means not specific
            print(
                f"\tEntry Point Address: \033[32m{elf_file.header.e_entry}\033[0m")
            # Offset from file beginning to Section Header
            # print(f"Section Header: {elf_file.header.e_type.e_shoff}")
            print(
                f"\tHeader Size: \033[32m{elf_file.header.e_ehsize} \033[33mbytes\033[0m")
            # EF_ARM_HASENTRY - contains a start address in the e_entry field
            # EF_ARM_INTERWORK -contains an ARM-compatible interworking symbol table.
            print(f"\tFlags: \033[32m{elf_file.header.e_flags}\033[0m")

            # Iterate over the program headers
            section_count = len(list(elf_file.iter_sections()))
            print(f"\tTotal section count: \033[36m{section_count}\033[0m")

    except Exception as e:
        print(f"An error occurred: {e}")


def get_sect_info(input_file):
    try:
        with open(input_file, "rb") as f:
            # Parse the ELF file
            elf_file = ELFFile(f)
            print(
                "\t\033[34m__________________________SECTIONS__________________________\033[0m")
            for section in elf_file.iter_sections():
                print(f"\t\033[35mName:\033[0m {section.name} \
\033[35mType:\033[0m {section['sh_type']} \033[35mAddress:\033[0m {section['sh_addr']} \
\033[35mSize:\033[0m {section['sh_size']} \033[35mOffset:\033[0m \
{section['sh_offset']} \033[35mFlags:\033[0m {section['sh_flags']}")

            print(
                "\t\033[34m__________________________Symbol table:__________________________`\033[0m")
            print("\nSymbol table:")
            for section in elf_file.iter_sections():
                if section.header['sh_type'] == 'SHT_SYMTAB':
                    symtab = section
                    break

                    if symtab.header['sh_size'] > 0:

                        for sym in symtab.iter_symbols():
                            print(f"\tSymbol name: \033[32m{sym.name}\033[0m")
                            print(
                                f"\tSymbol type: \033[32m{sym.entry.type}\033[0m")
                            print(
                                f"\tSymbol binding: \033[32m{sym.entry.st_info.binding}\033[0m")
                            print(
                                f"\tSymbol section: \033[32m{sym.entry.st_shndx}\033[0m")
                            print(
                                f"\tSymbol value: \033[32m{sym.entry.st_value}\033[0m")
                            print(
                                f"\tSymbol size: \033[32m{sym.entry.st_size}\033[0m")
    except KeyboardInterrupt:
        print("\nExiting")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")


def calc_hash(file_path):
    # Calculate the SHA-256 checksum of the malware
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        sha256_hash.update(f.read())
    sha256_checksum = sha256_hash.hexdigest()
    print(f'SHA-256 checksum: {sha256_checksum}')


'''def dynamic_analysis(sample_path):
    # Get the process list before executing the malware sample
    process_list_before = subprocess.get_process_list()

    # Execute the malware sample in a sandboxed environment
    sandboxed_execution(sample_path)

    # Get the process list after executing the malware sample
    process_list_after = subprocess.get_process_list()

    # Find the new processes created by the malware sample
    new_processes = list(set(process_list_after) - set(process_list_before))
    logger.info("Ananlysis logged in marep.log")
    with open('marep.log', 'a') as log:
        log.writelines(new_processes)
    # Get the vulnerability exploited by the malware sample
    vulnerability = get_vulnerability(sample_path)
    return vulnerability, new_processes'''


def get_elf_infor(input_file):
    if is_elf(input_file):

        return elfparser(input_file), get_sect_info(input_file)
    else:
        logger.error('\033[36m File not PE file\033[0m')
        return False


if __name__ == '__main__':
    get_elf_infor(
        '/home/user/MAREP/malware/desquirr.plw')
