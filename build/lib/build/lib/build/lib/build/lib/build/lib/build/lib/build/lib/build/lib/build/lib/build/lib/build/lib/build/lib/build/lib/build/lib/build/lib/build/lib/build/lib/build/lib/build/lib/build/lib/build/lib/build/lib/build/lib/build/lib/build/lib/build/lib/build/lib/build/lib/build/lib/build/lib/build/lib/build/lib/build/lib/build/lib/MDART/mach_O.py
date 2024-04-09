import capstone
import r2pipe
import yara
import hashlib
import os
import subprocess
from macholib.MachO import load_command
from macholib.MachO import MachO


def is_mach_o(binary_path):
    try:
        with open(binary_path, 'rb') as f:
            data = f.read(4)

        if data == b'\xcf\xfa\xed\xfe':
            return True
        else:
            return False
    except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
        print(f'Error: {e}. Please ensure the file exists and you have\
              read permissions.')
        return False


def get_macho_header_info(file_path):
    try:
        macho = MachO(file_path)
        macho_header = macho.lf_header
        print(f"Magic number >target system arch: {macho_header.e_machine}")
        print(f"CPU type: {macho_header.e_type}")
        print(f"CPU subtype: {macho_header.e_subtype}")
        print(f"File type: {macho_header.e_type}")
        print(f"Number of load commands: {macho_header.e_ncmds}")
        print(f"Size of load commands: {macho_header.e_sizeofcmds}")
        print(f"Flags: {macho_header.e_flags}")
        print(f"Reserved: {macho_header.e_reserved}")

    except Exception as e:
        print(f"Error parsing Mach-O file: {e}")


def get_macho_load_commands(file_path):
    try:
        macho = MachO(file_path)
        # get load commands(describe file section, segments, structure)
        for cmd in load_commands(macho):
            print(f"Load command type: {cmd.name}")
            print(f"Load command size: {cmd.length}")
            print(f"Load command data: {cmd.data}", end='\n')
        # get segments (contain code or data described by load commands)
        for segment in macho.segments:
            print(f"Segment name: {segment.Name}")
            print(f"Segment virtual address: {segment.VirtualAddress}")
            print(f"Segment size: {segment.SizeOfRawData}")
            print(f"Segment permissions: {segment.Characteristics}")
        # get symbols (they represent functions,variables etc)
        for symbol in macho.symbols:
            print(f"Symbol name: {symbol.name}")
            print(f"Symbol type: {symbol.type}")
            print(f"Symbol description: {symbol.desc}")
            print(f"Symbol section: {symbol.section}")
            print(f"Symbol value: {symbol.value}")
            print(f"Symbol size: {symbol.size}")
    except Exception as e:
        print(f"Error parsing Mach-O file: {e}")


# Capstone detection
def capstone_detection(path):
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()

        md = capstone.Cs(capstone.CS_ARCH_X86_64, capstone.CS_MODE_64)
        for i in md.disasm(data, 0):
            if i.mnemonic == 'int3' or i.mnemonic == 'int1':
                malware_type = 'Capstone Detection'
                return True, malware_type
    except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
        print(f'Error: {e}. Please ensure the file exists and you have\
              read permissions.')
        return False, None


def calc_hash(sample_path):
    # Calculate the SHA-256 checksum of the malware sample
    sha256_hash = hashlib.sha256()
    with open(sample_path, 'rb') as f:
        sha256_hash.update(f.read())
    sha256_checksum = sha256_hash.hexdigest()
    return sha256_checksum


def get_macho_info(input_file):
    if detect_malware(sample_path):
        malware_detected, malware_type = detect_malware(input_file)

        if malware_detected:
            calc_hash(input_file)
            dynamic_analysis(input_file)

        print(f"Malware file{input_file}")
        print(f'Malware detected: {malware_type}')
        print(f'SHA-256 checksum: {sha256_checksum}')
        print(f'Type: {malware_type}')
        print(f'Effect on the system: {new_processes}')
        print(f'Vulnerability exploited: {vulnerability}')
    else:
        print('No malware detected.')
