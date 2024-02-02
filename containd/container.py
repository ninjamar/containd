import os
import uuid
from ctypes import CFUNCTYPE, c_int, CDLL
from .flags import *
from .utils import (
    _write_cgroup_rule,
    _mk_cgroup,
    _allocate_stack,
    root_required,
    purge_all,
)

libc = CDLL("libc.so.6")


@root_required
class Container:
    def __init__(
        self,
        rootfs_path=None,
        pids_max="max",
        memory_max="max",
        stacksize_A=65536,
        stacksize_B=1,
    ):
        self.id = uuid.uuid4().hex
        self.configure(
            rootfs_path=rootfs_path,
            pids_max=pids_max,
            memory_max=memory_max,
            stacksize_A=stacksize_A,
            stacksize_B=stacksize_B,
        )

        self.cgroup_relpath = "containd/" + self.id + "/"
        self.cgroup_abspath = "/sys/fs/cgroup/" + self.cgroup_relpath

        _mk_cgroup("root", "root", "memory,pids", self.cgroup_relpath)

    def configure(
        self,
        rootfs_path=None,
        pids_max=None,
        memory_max=None,
        stacksize_A=None,
        stacksize_B=None,
    ):
        if rootfs_path != None:
            self.rootfs_path = rootfs_path
        if pids_max != None:
            self.pids_max = pids_max
        if memory_max != None:
            self.memory_max = memory_max
        if stacksize_A != None:
            self.stacksize_A = stacksize_A
        if stacksize_B != None:
            self.stacksize_B = stacksize_B

    def _ensure_cgroup_limits(self):
        _write_cgroup_rule(self.cgroup_abspath + "cgroup.procs", os.getpid())
        _write_cgroup_rule(self.cgroup_abspath + "pids.max", self.pids_max)
        _write_cgroup_rule(self.cgroup_abspath + "memory.max", self.memory_max)

    def _setup_root(self):
        os.chroot(self.rootfs_path)
        os.chdir("/")

    def _jail_setup_variables(self):
        libc.clearenv()
        os.environ["TERM"] = "xterm-256color"
        os.environ["PATH"] = "/bin/:/sbin/:/usr/bin/:/usr/sbin"

    def _jail_setup_fs(self):
        libc.mount("proc".encode(), "/proc".encode(), "proc".encode(), 0, 0)
        libc.mount("dev".encode(), "/dev".encode(), "devtmpfs".encode(), 0, 0)
        libc.mount("sys".encode(), "/sys".encode(), "sysfs".encode(), 0, 0)

    def _jail_cleanup(self):
        libc.umount("/proc".encode())
        libc.umount("/dev".encode())
        libc.umount("/sys".encode())

    def _clone_process(self, fn, ssize, flags):
        libc.clone(CFUNCTYPE(c_int)(fn), _allocate_stack(ssize), flags)
        libc.wait()  # os.wait needs SIGCHLD as a flag

    def _cleanup(self):
        # We should remove current cgroup, however this seems to fail since the device is in use. The solution is to empty cgroup.procs
        purge_all()  # At minimum, cleanup directory

    def run(self, cmd):
        def jail():
            self._setup_root()  # Root set belongs in child since we need to exit sandbox on function exit
            self._jail_setup_fs()
            self._jail_setup_variables()

            def inner():
                os.execvp(cmd, [cmd])
                return 0

            self._clone_process(
                inner, self.stacksize_B, SIGCHLD | CLONE_NEWPID
            )  # Somehow the stack size fixes everything
            self._jail_cleanup()
            return 0  # Must return

        self._ensure_cgroup_limits()
        self._clone_process(
            jail,
            self.stacksize_A,
            CLONE_NEWNS
            | CLONE_NEWNET  #
            | CLONE_NEWIPC
            | CLONE_NEWUSER  # create a new user system - this makes default user not root
            | CLONE_NEWPID
            | CLONE_NEWUTS
            | CLONE_NEWCGROUP  # this is so specific - disable cgroup sharing
            | SIGCHLD,
        )
        self._cleanup()
