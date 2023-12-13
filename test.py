import containd

container = containd.Container(rootfs_path="rootfs", pids_max=32)
container.run("/bin/sh")