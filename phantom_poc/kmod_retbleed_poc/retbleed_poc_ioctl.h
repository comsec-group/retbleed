// SPDX-License-Identifier: GPL-3.0-only
#define PROC_RETBLEED_POC "retbleed_poc"

#define REQ_GADGET    222
#define REQ_SPECULATE 111

struct synth_gadget_desc {
  unsigned long physmap_base;
  unsigned long kbr_dst;
  unsigned long kbr_src;
  unsigned long last_tgt;
  unsigned long secret;
};

struct payload {
    unsigned long reload_buffer;
    unsigned long secret;
};
