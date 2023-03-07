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

specs = [get_specs(x + "/specs") for x in dirs]

res = []
for i in range(15, 36):
    tmp = f"| {i} "
    for j in range(len(specs)):
        try:
            tmp += f"| {specs[j][i - 15][1] * 1000.0} "
        except:
            tmp += f"| none "
    tmp += "|"
    res.append(tmp)

print("\n".join(res))


res = []
for i in range(15, 36):
    tmp = f"| {i} "
    for j in range(len(specs)):
        try:
            tmp += f"| {specs[j][i - 15][2] / (1024.0 * 8.0)} "
        except:
            tmp += f"| none "
    tmp += "|"
    res.append(tmp)

print("\n".join(res))
