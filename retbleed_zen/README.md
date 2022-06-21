# Retbleed

We provide the following.

- `pocs/`. Here we demonstrate the presence of primitives that are used for 1)
    showing BTI on return instructions and 2) showing that it can be used in the
    kernel via a kernel module provided under `pocs/kmod_retbleed_poc/`.
- `exploits/`. Here we demonstrate the steps necessary to 1) break KASLR, 2)
    find the physical address our reload buffer (for F+R leaking), 3) finding
    the base pointer for direct mapped memory (`page_offset_base` aka.
    _physmap_) and finally 4) leak some piece of data from the kernel. For a
    minimal PoC, see exploits/break_kaslr.c.

Please bear in mind that side-channels are messy and often requires some manual
tweaking for them to start working. We provide a video demonstrating the effect
on two different Zen2 machines.

We have tested it on the following setups.
- AMD Ryzen 7 PRO 4750U and AMD EPYC 7252
- Debian clang version 11.0.1-2 and clang version 10.0.0-4ubuntu1
- Ubuntu 20.04 with kernel 5.8.0-63-generic and Debian 11 with a home built
  5.10 kernel
- **NOTE:** Exploits will not work on any other kernel.
