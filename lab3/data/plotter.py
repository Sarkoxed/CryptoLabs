import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from sys import argv
from math import log


def get_plot(ylabel, unit, filename, all_ts, n):
    plt.clf()

    sns.set_style("darkgrid")
    plt.rc("axes", titlesize=18)
    plt.rc("axes", labelsize=14)
    plt.rc("xtick", labelsize=7)
    plt.rc("ytick", labelsize=8)
    plt.rc("legend", fontsize=12)
    plt.rc("font", size=13)

    sns.color_palette("bright")

    p = sns.lineplot(x="Bytes", y=ylabel, hue="MAC", marker=".", data=all_ts)
    p.set_xlabel("Bytes, num", fontsize=14)
    p.set_ylabel(f"{ylabel}, {unit}", fontsize=14)
   
    colors = ["blue", "orange", "green", "red", "cyan", "pink"]
    for i in range(n):
        l1 = p.lines[i]
        x1 = l1.get_xydata()[:, 0]
        y1 = l1.get_xydata()[:, 1]
        p.fill_between(x1, y1, color=colors[i], alpha=0.1)

    p.margins(x=0, y=0)
    p.figure.savefig(filename)


def get_specs(filename):
    with open(filename, "rt") as f:
        s = f.read().split('\n')[1:-1]
    res = []
    for tmp in s:
        n, t = tmp.split()
        n = int(n)
        t = float(t)
        res.append((n, t))
    return res


dirs = ["omac", "hmac", "tcbc"]
total_time_df = pd.DataFrame([], columns=None)

for mac in dirs:
    cur_spec = get_specs(mac + "/specs")

    time_ds = [[log(x[0]), x[1] * 1000.0, mac.upper()] for x in cur_spec]
    time_columns = ["Bytes", "AvgTime", "MAC"]
    time_df = pd.DataFrame(time_ds, columns=time_columns)

    total_time_df = pd.concat([total_time_df, time_df])

get_plot("AvgTime", "ms", "TimingLog", total_time_df, len(dirs))
