import matplotlib.pyplot as plt
from sage.all import srange, floor, ceil
import seaborn as sns
import pandas as pd
from sys import argv


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

    p = sns.lineplot(x="Bits", y=ylabel, hue="Attack", marker=".", data=all_ts)
    p.set_xlabel("Bits, num", fontsize=14)
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
        n, t, m = tmp.split()
        n = int(n)
        t = float(t)
        m = float(m)
        res.append((n, t, m))
    return res


dirs = ["birthday", "pollard_short", "pollard_full", "pollard_own_short", "pollard_own_full"]
#dirs = ["birthday", "pollard_short", "pollard_own_short"]

for attack in dirs:
    total_time_df = pd.DataFrame([], columns=None)
    total_meme_df = pd.DataFrame([], columns=None)

    cur_spec = get_specs(attack + "/specs")

    time_ds = [[x[0], x[1] * 1000.0, attack] for x in cur_spec]
    time_columns = ["Bits", "AvgTime", "Attack"]
    time_df = pd.DataFrame(time_ds, columns=time_columns)

    mem_ds = [[x[0], x[2] / (8.0 * 1024.0), attack] for x in cur_spec]
    mem_columns = ["Bits", "AvgMem", "Attack"]
    mem_df = pd.DataFrame(mem_ds, columns=mem_columns)
    
    total_time_df = pd.concat([total_time_df, time_df])
    total_meme_df = pd.concat([total_meme_df, mem_df])
    
    print("Timing_" + attack)
    get_plot("AvgTime", "ms", "Timing_" + attack, total_time_df, 1)
    get_plot("AvgMem", "Kb", "Memory_" + attack, total_meme_df, 1)

dirs = ["birthday", "pollard_short", "pollard_own_short"]
total_time_df = pd.DataFrame([], columns=None)
total_meme_df = pd.DataFrame([], columns=None)
bit_bound = 6

for attack in dirs:
    cur_spec = get_specs(attack + "/specs")[:bit_bound]

    time_ds = [[x[0], x[1] * 1000.0, attack] for x in cur_spec]
    time_columns = ["Bits", "AvgTime", "Attack"]
    time_df = pd.DataFrame(time_ds, columns=time_columns)

    mem_ds = [[x[0], x[2] / (8.0 * 1024.0), attack] for x in cur_spec]
    mem_columns = ["Bits", "AvgMem", "Attack"]
    mem_df = pd.DataFrame(mem_ds, columns=mem_columns)
    
    total_time_df = pd.concat([total_time_df, time_df])
    total_meme_df = pd.concat([total_meme_df, mem_df])

print("Timing_20")
get_plot("AvgTime", "ms", "Timing_20", total_time_df, 5)
get_plot("AvgMem", "Kb", "Memory_20", total_meme_df, 5)
