import subprocess
from ctypes import c_char_p, c_void_p, cast
import os


def _allocate_stack(ssize):
    # https://stackoverflow.com/a/13374670/21322342
    stack = c_char_p((" " * ssize).encode("utf-8"))
    return c_void_p(cast(stack, c_void_p).value + (ssize - 1))


def _mk_cgroup(a, b, controllers, relpath):
    subprocess.run(
        ["cgcreate", "-t", a, "-a", b, "-g", f"{controllers}:{relpath}"],
        capture_output=True,
        text=True,
    )


def _rm_cgroup(controllers, relpath):
    subprocess.run(
        ["cgdelete", "-g", f"{controllers}:{relpath}"],
        capture_output=True,
        text=True,
    )


def _write_cgroup(abspath, value):
    with open(abspath, "w") as f:
        f.write(str(value))


def purge_all():
    # return [x[0] for x in os.walk("/sys/fs/cgroup/containd/")]
    dirs = next(os.walk("/sys/fs/cgroup/containd"))[1]
    for d in dirs:
        _rm_cgroup("memory,pid", "containd/" + d)
