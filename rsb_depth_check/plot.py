import matplotlib
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

import sys
if len(sys.argv) < 3:
    print(f"useage: {sys.argv[0]} <ret> <jmp>")
    exit(1)
file_ret = sys.argv[1]
file_jmp = sys.argv[2]

#  matplotlib.rcParams['font.family'] = 'serif'
#  sb.set()
fig, ax = plt.subplots()
fig.set_figwidth(5)
fig.set_figheight(1.75)

with open(file_ret) as f:
    with open(file_jmp) as f2:
        lines_ret = f.readlines()[1:]
        lines_jmp = f2.readlines()[1:]
        nx = min(len(lines_ret), len(lines_jmp))

        xs = []
        ys = []
        for i in range(nx):
            x = i
            y = lines_ret[i]
            #[x, y] = [int(n) for n in lines_ret[i].split(";")]
            xs.append(x)
            ys.append(y)
        ax.plot(xs, ys, label="return")
        ax.set_xlim(left=0, right=35)

        xs = []
        ys = []
        for i in range(nx):
            #[x, y] = [int(n) for n in lines_jmp[i].split(";")]
            x = i
            y = lines_jmp[i]
            xs.append(x)
            ys.append(y)
        ax.plot(xs, ys, label="indirect branch")
        ax.set_xlim(left=0, right=35)
ax.grid()
ax.axvline(x=16, color='0.3', linestyle='--', label="Intel RSB capacity");
ax.legend()
xlabel =ax.set_xlabel('# branches')
ylabel = ax.set_ylabel("mispredictions")

ax.xaxis.set_major_locator(ticker.MultipleLocator(4))
ax.yaxis.set_major_locator(ticker.MultipleLocator(14))
fig.tight_layout()
fig.savefig("ret-btb-miss.pdf")

