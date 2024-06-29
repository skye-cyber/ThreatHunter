'''This is an example using some popular Python libraries for reversing and
analyzing PE files – a common format for executable files on Windows systems.
This example focuses on extracting basic information about a given PE file.'''
# import os
import sys
from pefile import PE
# import pymem
import logging
import logging.handlers

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)


def is_pe(binary_path):
    try:
        with open(binary_path, 'rb') as f:
            data = f.read(2)

        if data == b'MZ':
            return True
        else:
            return False
    except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
        logger.error(f'{e}')


def get_infor(input_file):
    pe = PE(input_file)
    try:
        print(
            "\033[1;36m______________________DOS Header Information______________________\033[0m\n")
        print(f"Magic Number: \033[35m{pe.DOS_HEADER.e_magic}\033[0m")
        print(f"Signature: \033[35m{pe.NT_HEADERS.Signature}\033[0m")

        '''This is a 4-byte unsigned integer representing the minimum amount of
    memory (in paragraphs, where 1 paragraph = 16 bytes) required for the
    program when it starts execution.'''
        print(
            f"Minimum memory allocation: \033[35m{pe.DOS_HEADER.e_minalloc}\033[0m")

        '''Maximum'''
        print(
            f"Maximum memory allocation: \033[35m{pe.DOS_HEADER.e_maxalloc}\033[0m")

        '''This is a 4-byte reserved space that should always be zeroed out;
        it is not used by the loader or the application'''
        print(f"Reserved Space: \033[35m{str(pe.DOS_HEADER.e_res)}\033[0m")

        '''The checksum helps verify the integrity of the DOS header.'''
        print(f"Header CheckSum: \033[35m{pe.DOS_HEADER.e_csum}\033[0m")

        '''offset from the beginning of the file to the optional header.
        It allows the loader to quickly locate the NT headers without parsing
        the entire DOS header.'''
        print(f"Header Offset: \033[35m{pe.DOS_HEADER.e_lfanew}\033[0m")

        '''older versions of the PE file format'''
        print(
            f"Raw data Length: \033[35m{pe.DOS_HEADER.e_lfarlc}\033[0m")

        '''This is a 4-byte unsigned integer that represents the CRC
        (Cyclic Redundancy Check) value of the raw data section.
        The CRC helps ensure the integrity of the data in the file.'''
        print(
            f"Cyclic Redundancy Check: \033[35m{pe.DOS_HEADER.e_crlc}\033[0m")

        '''2-byte unsigned short that specifies the code page number.
        The code page determines the character encoding used in the executable.
        '''
        print(f"Code Page: \033[35m{pe.DOS_HEADER.e_cp}\033[0m")

        '''2-byte unsigned short that indicates the size of the new exe header,
        including the DOS header itself and any overlays.'''
        print(f"New exe size: \033[35m{pe.DOS_HEADER.e_cblp}\033[0m")

        print(
            "\033[1;36m______________________FILE_HEADER Information______________________\033[0m\n")
        # print(f"Signature: {pe.DIRECTORY_ENTRY}")
        print(f"Machine: \033[35m{pe.FILE_HEADER.Machine}\033[0m")
        print(
            f"Number Of Sections: \033[35m{pe.FILE_HEADER.NumberOfSections}\033[0m")
        print(
            f"Time Date Stamp: \033[35m{pe.FILE_HEADER.TimeDateStamp}\033[0m")
        print(
            f"Number Of Symbols: \033[35m{pe.FILE_HEADER.NumberOfSymbols}\033[0m")
        print(
            f"Size Of Optional Header: \033[35m{pe.FILE_HEADER.SizeOfOptionalHeader}\033[0m")
        print(
            f"Characteristics: \033[35m{pe.FILE_HEADER.Characteristics}\033[0m")

        print(
            "\033[1;36m______________________OPTIONAL_HEADER Information______________________\033[0m\n")

        print(f"Magic Number: \033[35m{pe.OPTIONAL_HEADER.Magic}\033[0m")
        print(f"Size Of Code: \033[35m{pe.OPTIONAL_HEADER.SizeOfCode}\033[0m")
        print(
            f"Major Operating System Version: \033[35m{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}\033[0m")
        print(
            f"Minor Operating System Versio: \033[35m{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}\033[0m")
        print(
            f"MajorSubsystemVersion: \033[35m{pe.OPTIONAL_HEADER.MajorSubsystemVersion}\033[0m")
        print(f"LoaderFlags: \033[35m{pe.OPTIONAL_HEADER.LoaderFlags}\033[0m")
        print(
            f"NumberOfRvaAndSizes: \033[35m{pe.OPTIONAL_HEADER.NumberOfRvaAndSizes}\033[0m")
        print(
            f"DllCharacteristics: \033[35m{pe.OPTIONAL_HEADER.DllCharacteristics}\033[0m")
        print(f"CheckSum: \033[35m{pe.OPTIONAL_HEADER.CheckSum}\033[0m")

        print(
            "\033[1;36m______________________PE SECTIONS Information______________________\033[0m\n")

        for section in pe.sections:
            print(f"Name: \033[35m{str(section.Name[:5])}\033[0m Lines:\033[35m\
{section.NumberOfLinenumbers}\033[0m Misc:\033[35m{section.Misc}\033[0m")

        for i in pe.VS_VERSIONINFO:
            print(f"Length: \033[35m{i.Length}\033[0m Value Length: \033[35m\
{i.ValueLength}\033[0m Type: \033[35m{i.Type}\033[0m")

        for item in pe.VS_FIXEDFILEINFO:
            print(
                "\033[1;36m______________________VS_FIXEDFILEINFO______________________\033[0m\n")
            print(f"FileType: \033[35m{item.FileType}\033[0m")
            print(f"FileOS: \033[35m{item.FileOS}\033[0m")
            print(f"FileFlags: \033[35m{item.FileFlags}\033[0m")
            print(f"FileVersionMS: \033[35m{item.FileVersionMS}\033[0m")
            print(f"FileVersionLS: \033[35m{item.FileVersionLS}\033[0m")

        print(
            "\033[1;36m______________________OTHER INFO______________________\033[0m\n")

        print(
            f"InternalName: \033[35m{pe.StringFileInfo.StringTable.InternalName}\033[0m")
        print(
            f"FileDescription: \033[35m{pe.StringFileInfo.StringTable.FileDescription}\033[0m")
        print(
            f"LegalCopyright: \033[35m{pe.StringFileInfo.StringTable.LegalCopyright}\033[0m")
        print(
            f"OriginalFilename: \033[35m{pe.StringFileInfo.StringTable.OriginalFilename}\033[0m")

    except KeyboardInterrupt:
        print("\nExiting")
        sys.exit(1)
    except Exception:
        pass


def get_pe_infor(input_file):
    if is_pe(input_file):
        get_infor(input_file)
    else:
        logger.error('\033[1;36m File not PE file\033[0m')
        pass


if __name__ == "__main__":
    get_pe_infor(
        '/home/user/MAREP/malware/desquirr.plw')
