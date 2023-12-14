import containd

container = containd.Container(
    rootfs_path="rootfs",
    pids_max=32,
    # memory_max=1 * 1000000
    memory_max=1560000,  # This seems to be the bare minimum of memory that will launch the shell
)  # 1 mb of memory
container.configure(memory_max=10000000)
container.run("/bin/sh")
