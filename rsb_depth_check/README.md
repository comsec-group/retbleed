# rsb_depth_check

It builds for intel by default. Go into ./ret_chain.c and comment out 
`#define INTEL` to make it for AMD.

Use `./run_test.sh <output_dir>` to run the test. Then use `python3 plot.py
<output_dir>/ret.txt <output_dir>/jmp.txt` to plot.

