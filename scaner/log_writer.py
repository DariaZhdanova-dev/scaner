import inspect
from enum import auto, Flag
import sys


class Mode(Flag):
    REVIEW = auto()
    SINGLE_PROC = auto()


class ResType(Flag):
    SUCCESS = auto()
    INFO = auto()
    ACTION = auto()
    FAIL = auto()
    NO_LABEL = auto()


PRINT_MODE = Mode.REVIEW


def print_msg(md: list[Mode], res_type: ResType, data: str) -> None:
    if PRINT_MODE in md or len(md) == 0:
        if res_type == ResType.SUCCESS:
            print('[+] ', end='')
        elif res_type == ResType.INFO:
            print('[#] ', end='')
        elif res_type == ResType.ACTION:
            print('[?] ', end='')
        elif res_type == ResType.FAIL:
            caller_name = inspect.currentframe().f_back.f_code.co_name
            print(f'[-] [{caller_name}] ', end='')

        print(data)


