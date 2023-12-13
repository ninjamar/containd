import containd

container = containd.Container(options={
    "rootfs_path": "rootfs",
    "pids.max": 32,
    "memory.max": "max",
    "stacksize_A": 65526,
    "stacksize_B": 1
})
container.run("/bin/sh")
