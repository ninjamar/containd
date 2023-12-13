import containd

container = containd.Container(rootfs_path="rootfs")
print(container.cgroup_relpath)
container.run("/bin/sh")
