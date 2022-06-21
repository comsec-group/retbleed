#!/bin/bash
img=$1
user=$2
/usr/bin/qemu-system-x86_64 -drive "file=${img},format=qcow2" -drive "file=${user},format=raw" -s \
-m 2G \
-cpu host \
-smp 12 \
-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
-net nic,model=e1000 \
-enable-kvm \
-nographic \
-pidfile vm.pid 2>&1 | tee erro.log
