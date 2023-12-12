import os

if (
    os.getuid() != 0
):  # Module must be running as root - TODO: This might be changed in future versions
    raise Exception("Module must be run as root")

from ctypes import CDLL

libc = CDLL("libc.so.6")

from .container import *
