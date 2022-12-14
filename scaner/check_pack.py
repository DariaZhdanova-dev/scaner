import os
import psutil
import pypackerdetect as pypackerdetect
from .log_writer import *


def check_packer(pid: int) -> tuple[bool, str]:
    p = psutil.Process(pid)
    print_msg([Mode.SINGLE_PROC], ResType.INFO, f'Exe path: {p.exe()}')
    if not os.path.exists(p.exe()):
        print_msg([], ResType.FAIL, "File not found")
        return False, "File not found"

    packer = pypackerdetect.PyPackerDetect()
    try:
        result = packer.detect(p.exe())
        if len(result["detections"]) == 0:
            print_msg([Mode.SINGLE_PROC], ResType.INFO, "No packers found")
            return False, "No packers found"
        print_msg([Mode.REVIEW], ResType.INFO, "Image packed")
        print_msg([Mode.SINGLE_PROC], ResType.INFO, "Found packer:")
        print_msg([Mode.SINGLE_PROC], ResType.INFO, result["detections"])
        return True, f"Image packed\nFound packer:\n{result['detections']}"
    except Exception as err:
        print_msg([], ResType.FAIL, str(err))
        return False, str(err)


if __name__ == '__main__':
    check_packer(10184)
