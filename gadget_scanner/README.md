## Retbleed Disclosure gadget scanner

This is a basic scanner that we used in the retbleed paper. Note that a gadget
scanner is useful for all BTI Spectre attacks, such as the recent BHI paper.

```sh
pip install capstone
# run the tests
./tests
# run the scanner
./gadget.py vmlinux [start_va]
```

### Test cases

- `secret_first` currently fails. I never added support for this case
- There's also no "manifest file" or some kind of metadata that says what
    control each test case is supposed to have. Instead, they are all assumed to
    have contorl over memory pointed to by `r13+0x8...r13+0x108`

### Reproduce our results
For vulnerable return we had control over memory pointer to be
`r14+0x8...0x108`. To find a disclosure gadget for this, uncomment L16 and
comment out L17 in `gadget.py`. A vmlinux of 5.8-0-63-generic is provided.

Then run `./gadget.py vmlinux 0xffffffff813db000`. Last argument is optional but
speeds things up the search by starting near the gadget. 
