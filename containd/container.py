import os
import uuid
import configparser
from ctypes import CFUNCTYPE, c_int, CDLL
from .flags import *
from .utils import _write_cgroup, _mk_cgroup, _rm_cgroup, _allocate_stack

libc = CDLL("libc.so.6")
BASE_CONFIGURATION_PATH = os.path.expanduser(
    f"~{os.environ.get('SUDO_USER', 'root')}/.containd"
)


class Container:
    def __init__(self, _id=None, _DEBUG_SKIP=False, options={}):
        if os.getuid() != 0:
            raise Exception("Container must be run as root")
        self.config = {}
        if not _DEBUG_SKIP:  # Temp should still assign id but clear cgroup on leave
            if not os.path.exists(BASE_CONFIGURATION_PATH):
                os.mknod(BASE_CONFIGURATION_PATH)
            if _id is not None:  # id given
                config = configparser.ConfigParser()
                config.read(BASE_CONFIGURATION_PATH)

                for key in config[_id].keys():  # unpack configuration
                    self.config[key] = config[_id][key]
                    self.config["id"] = _id

                self._ensure_cgroup_by_id(_id)
            else:  # manually create a new config
                config = configparser.ConfigParser()
                config.read(BASE_CONFIGURATION_PATH)
                _id = uuid.uuid4().hex
                for key, value in options.items():
                    self.config[key] = value
                self.config["id"] = _id
                #  self._extract_config(config, _id)

                with open(BASE_CONFIGURATION_PATH, "w") as f:
                    config.write(f)

                self._ensure_cgroup_by_id(_id)
        else:  # no storage of configuration
            self.config = options  # TODO: is valid?
            self.config["id"] = -1

        self.id = self.config["id"]  # Expose ID to the end user
        self.cgroup_relpath = "containd/" + self.id + "/"
        self.cgroup_abspath = "/sys/fs/cgroup/" + self.cgroup_relpath

    def _ensure_cgroup_limits(self):
        print(os.getpid(), self.config["pids.max"], self.config["memory.max"])
        _write_cgroup(self.cgroup_abspath + "cgroup.procs", os.getpid())
        _write_cgroup(self.cgroup_abspath + "pids.max", self.config["pids.max"])
        _write_cgroup(self.cgroup_abspath + "memory.max", self.config["memory.max"])

    def _ensure_cgroup_by_id(self, _id):
        # TODO: Don't create cgroup if it already exists
        _mk_cgroup(
            "root", "root", "memory,pids", "containd/" + _id
        )  #  groups use abs path
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
                inner, self.config["stacksize_B"], SIGCHLD
            )  # Somehow the stack size fixes everything
            self._jail_cleanup()
            return 0  # Must return

        self._ensure_cgroup_limits()
        self._clone_process(
            inner, self.config["stacksize_A"], CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD
        )
        self._cleanup()
