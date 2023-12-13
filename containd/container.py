import os
import uuid
from ctypes import CFUNCTYPE, c_int, CDLL
from .flags import *
from .utils import _write_cgroup, _mk_cgroup, _rm_cgroup, _allocate_stack, root_required

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
        # if os.getuid() != 0:
        #    raise Exception("Container must be run as root")

        self.id = uuid.uuid4().hex
        self.rootfs_path = rootfs_path
        self.pids_max = pids_max
        self.memory_max = memory_max
        self.stacksize_A = stacksize_A
        self.stacksize_B = stacksize_B

        self.cgroup_relpath = "containd/" + self.id + "/"
        self.cgroup_abspath = "/sys/fs/cgroup/" + self.cgroup_relpath

    def _ensure_cgroup_limits(self):
        _write_cgroup(self.cgroup_abspath + "cgroup.procs", os.getpid())
        _write_cgroup(self.cgroup_abspath + "pids.max", self.pids_max)
        _write_cgroup(self.cgroup_abspath + "memory.max", self.memory_max)

    def _ensure_cgroup_by_id(self, _id):
        # TODO: Don't create cgroup if it already exists
        _mk_cgroup(
            "root", "root", "memory,pids", "containd/" + _id
        )  #  groups use abs path

    def _setup_root(self):
        os.chroot(self.rootfs_path)
        os.chdir("/")

    def _jail_setup_variables(self):
        libc.clearenv()
        os.environ["TERM"] = "xterm-256color"
        os.environ["PATH"] = "/bin/:/sbin/:/usr/bin/:/usr/sbin"

    def _jail_setup_fs(self):
        libc.mount(
            "proc".encode(), "/proc".encode(), "proc".encode(), 0, 0
        )  # libc str's must be byte's

    def _jail_cleanup(self):
        libc.umount("/proc".encode())

    def _clone_process(self, fn, ssize, flags):
        libc.clone(CFUNCTYPE(c_int)(fn), _allocate_stack(ssize), flags)
        libc.wait()  # os.wait needs SIGCHLD as a flag

    def _cleanup(self):
        _rm_cgroup("memory,pids", "containd/" + self.id)

    def run(self, cmd):
        def inner():
            self._setup_root()  # Root set belongs in child since we need to exit sandbox on function exit
            self._jail_setup_fs()
            self._jail_setup_variables()

            def inner():
                os.execvp(cmd, [cmd])
                return 0

            self._clone_process(
                inner, self.stacksize_B, SIGCHLD
            )  # Somehow the stack size fixes everything
            self._jail_cleanup()
            return 0  # Must return

        self._ensure_cgroup_limits()
        self._clone_process(
            inner, self.stacksize_A, CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD
        )
        self._cleanup()
