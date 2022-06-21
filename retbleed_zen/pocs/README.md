# Retbleed pocs

Two experiments are provided:

- `./ret_bti`. Shows that it is possible to generate BTB collision patterns on
    Zen1, Zen2 and Zen3 (but zen3 may need some tweaking to work).
- `./cp_bti`. Shows cross privilege boundary training possible. This PoC
    requires the kmod provided. `cd ./kmod_retbleed_poc && make install` it
    first.

