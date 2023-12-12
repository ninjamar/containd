import containd

container = containd.Container(rootfs_path="rootfs", _DEBUG_SKIP=False)
container.run("/bin/sh")
