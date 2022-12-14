import os
import pefile
import psutil

from .log_writer import *


def analyze_section(section):
    """
    https://blog.kowalczyk.info/articles/pefileformat.html
    0x00000020	Code section
    0x00000040	Initialized data section
    0x00000080	Uninitialized data section
    0x04000000	Section cannot be cached
    0x08000000	Section is not pageable
    0x10000000	Section is shared
    0x20000000	Executable section
    0x40000000	Readable section
    0x80000000	Writable section
    """
    r, w, x = False, False, False
    if (section.Characteristics & 0x00000020) or (section.Characteristics & 0x20000000):
        x = True
    if section.Characteristics & 0x80000000:
        w = True
    if section.Characteristics & 0x40000000:
        r = True

    result = ""
    result += "R" if r else "-"
    result += "W" if w else "-"
    result += "X" if x else "-"

    return result


def analyze_pe_file(pid: int):
    
    try:
        filepath = psutil.Process(pid).exe()
    except Exception:
        filepath = ""
        
    if not os.path.exists(filepath):
        return {}
    if not filepath[-4:] == ".exe":
        return {}

    try:
        print_msg([Mode.SINGLE_PROC], ResType.INFO, f"analyze_pe_file: {filepath}")

        pe = pefile.PE(filepath)
        result_struct = {}
        for section in pe.sections:
            result_struct[section.Misc_PhysicalAddress] = analyze_section(section)

        return result_struct
    except Exception as err:
        print_msg([Mode.SINGLE_PROC], ResType.FAIL, str(err))
        return {}
