import containd

container = containd.Container(rootfs_path="rootfs", _DEBUG_SKIP=False, remove_cgroup_on_cleanup=True)
#container = containd.Container(_id="eb982b66fc5346d3a438b9589c85a413", temp=True)
print(container.id)
container.run("/bin/sh")
