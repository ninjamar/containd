from pympler.tracker import SummaryTracker

tracker = SummaryTracker()

import containd

container = containd.Container(
    rootfs_path="rootfs",
    pids_max=32,
    memory_max="max",
    stacksize_A=65526,
    stacksize_B=1,
)
container.run("/bin/sh")

tracker.print_diff()
