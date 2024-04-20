# import struct
from pytudesigner import PE


def print_readably(field_name, field_value):
    if isinstance(field_value, int):
        # Print as hexadecimal with leading zeros and prefix '0x'
        print(f"{field_name}: {field_value:#010X}")
    elif isinstance(field_value, str):
        print(f"{field_name}: '{field_value}'")  # Print string directly
    else:
        print(f"{field_name}: {field_value}")  # Print other types directly


pe_file = PE.parse("path/to/your/pe_file.exe")
dos_header = pe_file.FILE_HEADER
nt_headers = pe_file.OPTIONAL_HEADER

print("File Header:")
print_readably("Magic Number", dos_header.MAGIC)
print_readably("Size of this header", dos_header.SIZE_OF_THIS_HEADER)
print_readably("Pointer to minitmxz", dos_header.MINITMXZ)
print_readably("Pointer to minitfxn", dos_header.MINITFXN)
print_readably("Pointer to rsrchdr", dos_header.RSRC_HDR)
print_readably("Size of image", dos_header.SIZE_OF_IMAGE)
print_readably("Pointer to slink", dos_header.SLINK)
print_readably("Number of relocations", dos_header.NUMBER_OF_RELOCATIONS)
print_readably("Number of exported names", dos_header.NUMBER_OF_EXPORTED_NAMES)
print_readably("TimeDateStamp", dos_header.TIMEDATESTAMP)
print_readably("Ptr to modifstm", dos_header.MODIFICATION_TIMESTAMP)
print_readably("CheckSum", dos_header.CHECKSUM)
print_readably("Subsystem", dos_header.SUBSYSTEM)
print_readably("Size of heap reservation", dos_header.SIZE_STACK_RESERVE)
print_readably("Minimum stack commitment", dos_header.MINIMUM_STACK_COMMIT)
print_readably("Maximum stack commitment", dos_header.MAXIMUM_STACK_COMMIT)
print_readably("Size of heap growth", dos_header.SIZE_STACK_GROWTH)
print("\nOptional Header:")
print_readably("Signature", nt_headers.SIGNATURE)
print_readably("Size of the file", nt_headers.SIZE_OF_IMAGE)
print_readably("Address of entry point", nt_headers.ENTRY_POINT)
print_readably("Number of sections", nt_headers.SECTION_COUNT)
print_readably("Text address", nt_headers.TEXT_ADDRESS)
print_readably("Extra overlay scroll", nt_headers.EXTRA_OVERLAY_SCROLL)
print_readably("Initial IP", nt_headers.INITIAL_IP)
print_readably("Reserved1", nt_headers.RESERVED1)
print_readably("Initial CS", nt_headers.INITIAL_CS)
print_readably("Initial RP", nt_headers.INITIAL_RP)
print_readably("Initial SP", nt_headers.INITIAL_SP)
print_readably("Required stack size", nt_headers.REQUIRED_STACK_SIZE)
print_readably("Stack reserve size", nt_headers.STACK_RESERVE_SIZE)
print_readably("Stack commit size", nt_headers.STACK_COMMIT_SIZE)
print_readably("Heap reserve size", nt_headers.HEAP_RESERVE_SIZE)
print_readably("Heap commit size", nt_headers.HEAP_COMMIT_SIZE)
print_readably("Loader flags", nt_headers.LOADER_FLAGS)
print_readably("Number of data directories",
               nt_headers.NUMBER_OF_DATA_DIRECTORIES)
print_readably("Entry point token", nt_headers.ENTRY_POINTER)
print_readably("Base of code", nt_headers.BASE_OF_CODE)
print_readably("Image base", nt_headers.IMAGE_BASE)
print_readably("Section alignment", nt_headers.SECTION_ALIGNMENT)
print_readably("File alignment", nt_headers.FILE_ALIGNMENT)
print_readably("Major operation system version",
               nt_headers.MAJOR_OPERATING_SYSTEM_VERSION)
print_readably("Minor operation system version",
               nt_headers.MINOR_OPERATING_SYSTEM_VERSION)
print_readably("Major image version", nt_headers.MAJOR_IMAGE_VERSION)
print_readably("Minor image version", nt_headers.MINOR_IMAGE_VERSION)
print_readably("Windows version", nt_headers.WINDOWS_VERSION)
print_readably("Size of image fixups", nt_headers.SIZE_OF_IMAGE_FIXUPS)
print_readably("Size of image data directory entries",
               nt_headers.SIZE_OF_IMAGE_DATA_DIR_ENTRIES)
print_readably("Size of an image import descriptor",
               nt_headers.SIZE_OF_IMAGE_IMPORT_DESCRIPTORS)
print_readably("Size of an image resource directory entry",
               nt_headers.SIZE_OF_IMAGE_RESOURCE_DIRECTORY_ENTRY)
