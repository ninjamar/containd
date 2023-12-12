import os
import uuid
import configparser
import subprocess
from ctypes import c_char_p, c_void_p, cast, CFUNCTYPE, CDLL, c_int
from .flags import *
from . import libc

BASE_CONFIGURATION_PATH = os.path.expanduser(f"~{os.environ['USER']}/.containd")


def _allocate_stack(ssize):
    # https://stackoverflow.com/a/13374670/21322342
    stack = c_char_p((" " * ssize).encode("utf-8"))
    return c_void_p(cast(stack, c_void_p).value + (ssize - 1))


def _mk_cgroup(a, b, controllers, path):
    result = subprocess.run(
        ["cgcreate", "-t", a, "-a", b, "-g", f"{controllers}:{path}"],
        capture_output=True,
        text=True,
    )

class Container:
    def __init__(
        self,
        _id=None,
        rootfs_path=None,
        stacksize_A=65536,
        stacksize_B=1,
        max_memory=1024,
        max_processes=8,
        _DEBUG_SKIP=False,
    ):
        self.config = {}
        if not _DEBUG_SKIP:
            if not os.path.exists(BASE_CONFIGURATION_PATH):
                os.mknod(BASE_CONFIGURATION_PATH)
            # cgroup structure /sys/fs/cgroup/containd/<id>/<resource>/<file>

            if _id is not None:  # id given
                config = configparser.ConfigParser()
                config.read(BASE_CONFIGURATION_PATH)
                self._extract_config(config, _id)
                self._ensure_cgroup_by_id(_id)
            else:  # manually create a new config
                config = configparser.ConfigParser()
                config.read(BASE_CONFIGURATION_PATH)
                _id = uuid.uuid4().hex
                config[_id] = {}
                config[_id]["rootfs_path"] = os.path.abspath(rootfs_path)
                config[_id]["stacksize_A"] = str(stacksize_A)
                config[_id]["stacksize_B"] = str(stacksize_B)
                config[_id]["max_memory"] = str(max_memory)
                config[_id]["max_processes"] = str(max_processes)
                self._extract_config(config, _id)
                with open(BASE_CONFIGURATION_PATH, "w") as f:
                    config.write(f)

                self._ensure_cgroup_by_id(_id)
        else:  # bypass cgroup for testing
            self.config["id"] = -1
            self.config["rootfs_path"] = os.path.abspath(rootfs_path)
            self.config["stacksize_A"] = int(stacksize_A)
            self.config["stacksize_B"] = int(stacksize_B)
            self.config["max_memory"] = int(max_memory)
            self.config["max_processes"] = int(max_processes)

        # self._main()

    def _extract_config(self, config, _id):
        self.config = {}
        self.config["id"] = _id
        self.config["rootfs_path"] = config[_id]["rootfs_path"]
        self.config["stacksize_A"] = int(config[_id]["stacksize_A"])
        self.config["stacksize_B"] = int(config[_id]["stacksize_B"])
        self.config["max_memory"] = int(config[_id]["max_memory"])
        self.config["max_processes"] = int(config[_id]["max_processes"])

    def _ensure_cgroup_by_id(self, _id):
        _mk_cgroup("root", "root", "memory,pids", "containd/" + _id) # for some reason, cgroups use abselute path
        # TODO, write cgroup from config

    def _setup_root(self):
        os.chroot(self.config["rootfs_path"])
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
        os.chroot("..")

    def run(self, cmd):
        def inner():
            self._jail_setup_fs()
            self._jail_setup_variables()

            def inner():
                # os.execvp("/bin/sh", ["/bin/sh"])
                os.execvp(cmd, [cmd])
                return 0

            self._clone_process(
                inner, self.config["stacksize_B"], SIGCHLD
            )  # Somehow the stack size fixes everything
            self._jail_cleanup()
            return 0  # Must return

        self._setup_root()
        self._clone_process(
            inner, self.config["stacksize_A"], CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD
        )
        self._cleanup()
