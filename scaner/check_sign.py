import psutil
import signify.authenticode.signed_pe
from .log_writer import *


def check_sign(path):
    try:
        with open(path, "rb") as f:
            pefile = signify.authenticode.signed_pe.SignedPEFile(f)
            status, err = pefile.explain_verify()

        return status == signify.authenticode.signed_pe.AuthenticodeVerificationResult.OK, err
    except FileNotFoundError:
        return False, "Not found"
    except Exception as err:
        return False, err


def check_proc_signatures(pid: int) -> bool:
    p = psutil.Process(pid)
    print_msg([Mode.SINGLE_PROC], ResType.INFO, f'Exe path: {p.exe()}')
    res, str_res = check_sign(p.exe())

    if not res:
        print_msg([Mode.SINGLE_PROC], ResType.INFO, f'Failed to check exe signature with error: {str_res}')
        print_msg([Mode.REVIEW], ResType.INFO, f'Exe signature check fail')
        return False
    for dll in p.memory_maps():
        print_msg([Mode.SINGLE_PROC], ResType.INFO, f'Dll path:: {p.exe()}')
        res, str_res = check_sign(dll.path)
        if not res:
            print_msg([Mode.SINGLE_PROC], ResType.INFO, f'Failed to check dll signature with error: {str_res}')
            print_msg([Mode.REVIEW], ResType.INFO, f'Dll signature check fail')
            return False

    print_msg([Mode.SINGLE_PROC], ResType.INFO, 'Process signature verified successfully')
    return True


if __name__ == '__main__':
    check_proc_signatures(23696)
