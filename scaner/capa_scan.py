import os
import subprocess
import psutil
from .log_writer import *


__dump_dir = os.path.join(os.getcwd(), 'dump')


def scan(pid: int) -> tuple[bool, str]:
    """
    capa scan

    Args:
        pid (int): pid

    Returns:
        tuple[bool, str]: result, msg
    """
    try:
        path = psutil.Process(pid).exe()
    except Exception:
        path = ""
        
    if len(path) == 0:
        #print_msg([], ResType.FAIL, 'Cannot find image path')
        return False, "Cannot find image path"

    scancmd = ['./scaner/capa.exe', path]

    with subprocess.Popen(scancmd, stdout=subprocess.PIPE) as proc:
        capa_out =  proc.stdout.read()
        #print(Mode.SINGLE_PROC, ResType.NO_LABEL, proc.stdout.read())

    return True, capa_out


if __name__ == '__main__':
    print(scan(23696))

    """
        scaner
        
    """