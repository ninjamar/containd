import subprocess
import os
import inspect
from ctypes import c_char_p, c_void_p, cast


def root_required(obj):
    def inner(*args, **kwargs):
        if os.getuid() != 0:
            raise Exception("Container must be run as root")
        return obj(*args, **kwargs)

    return inner


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


def _write_cgroup_rule(abspath, value):
    with open(abspath, "w") as f:
        f.write(str(value))


@root_required
def purge_all():
    dirs = next(os.walk("/sys/fs/cgroup/containd"))[1]
    for d in dirs:
        _rm_cgroup("memory,pid", "containd/" + d)
