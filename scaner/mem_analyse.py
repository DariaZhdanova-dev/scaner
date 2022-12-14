import os
import pprint
import subprocess
import pefile
import psutil
from . import pe_analyse
from .log_writer import *


__dump_dir = os.path.join(os.getcwd(), 'dump')


def dumper(pid: int):
    p = psutil.Process(pid)

    dumpcmd = ['pd64.exe', '-pid', str(pid), '-o', '.\\dump']

    for file in os.listdir(__dump_dir):
        os.remove(os.path.join(__dump_dir, file))
    proc = subprocess.run(dumpcmd, capture_output=True)
    if len(os.listdir(__dump_dir)) == 0:
        print_msg([Mode.SINGLE_PROC], ResType.FAIL, 'Error while creating dump')
        print_msg([Mode.SINGLE_PROC], ResType.FAIL, proc.args)
        print_msg([Mode.SINGLE_PROC], ResType.FAIL, proc.stdout)
        print_msg([Mode.SINGLE_PROC], ResType.FAIL, proc.stderr)
        print_msg([Mode.SINGLE_PROC], ResType.FAIL, f'Return code: {proc.returncode}')
        return False

    return True


def compare_mem_img(pid: int) -> bool:
    if not dumper(pid):
        print_msg([Mode.SINGLE_PROC], ResType.FAIL, 'Cannot dump process')
        return False, 'Cannot dump process'
    img = pefile.PE(name=psutil.Process(pid).exe())

    for file in os.listdir(__dump_dir):
        if file[-4:] == ".exe":
            path_dump = os.path.join(__dump_dir, file)
            break
    else:
        print_msg([Mode.SINGLE_PROC], ResType.FAIL, 'Cannot find dump')
        return False, 'Cannot find dump'

    proc_dump = pefile.PE(name=path_dump)

    print_msg([Mode.SINGLE_PROC], ResType.INFO, "Section count in image: {}".format(len(img.sections)))
    print_msg([Mode.SINGLE_PROC], ResType.INFO, "Section count in dump: {}".format(len(proc_dump.sections)))

    res = {}
    score = 0.0
    for i, (section1, section2) in enumerate(zip(img.sections, proc_dump.sections)):
        data_in_disk = section1.get_data()
        data_in_dump = section2.get_data()

        diff = set(data_in_dump) - set(data_in_disk)
        d = len(diff) / len(data_in_dump)

        res[section2.Misc_PhysicalAddress] = (d, pe_analyse.analyze_section(section2))
        score += d

    if score > 0.02:
        print_msg([Mode.SINGLE_PROC, Mode.REVIEW], ResType.INFO, "Process is modified")
        print_msg([Mode.SINGLE_PROC], ResType.INFO, res)
        return False, f"Process is modified\n{res}"

    pprint.pprint(res)
    print(score)
    return True, str(res)


if __name__ == '__main__':
    print(compare_mem_img(10544))
