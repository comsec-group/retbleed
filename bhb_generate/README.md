BHB generate
------------

Finds the branch history for a victim RET in the kernel using gdb.

### Steps
1. Set up a cloud image for example as described here https://powersj.io/posts/ubuntu-qemu-cli/
2. Boot. `./run_vm.sh focal-server-cloudimg-amd64.img user_config.img`.
3. Install the victim kernel on guest. E.g., `5.8.0-63-generic`, which was the latest at
   the time of carrying out this work. Reboot.
4. Add the interested test case `rsync -e 'ssh -p 10021' recvmsg02 ubuntu@127.0.0.1:`.
5. Check the `_text` offset of the guest. `sudo grep \ _text /proc/kallsyms`.
   Update `KB` in `./gdb_main.py` with the found Kernel Base address. 
6. In host run gdb, attach to guest: `target remote :1234` and `source gdb_main.py`.
7. The 29 last entries in log.txt is your BHB primer.
