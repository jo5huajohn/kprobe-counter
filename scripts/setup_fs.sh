#!/bin/bash

fallocate -l 10G ext4.disk
loop_dev=$(losetup -f --show ext4.disk)
mkfs.ext4 "$loop_dev"
mount "$loop_dev" /mnt
