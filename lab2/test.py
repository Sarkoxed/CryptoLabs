from hashlib import sha256

with open("out", "rt") as f:
    s = f.read().split("\n")[:-1]

s = [s[i:i + 7][1:4] for i in range(0, len(s), 7)]

for i, (x, y, z) in enumerate(s):
    a = x[4:]
    b = y[4:]
    c = z[7:]

    a = sha256(bytes.fromhex(a)).hexdigest()
    b = sha256(bytes.fromhex(b)).hexdigest()
    a = int(a, 16) % 2**(i + 1)
    b = int(b, 16) % 2**(i + 1)
    c = int(c, 16)
    
    try:
        assert a == b and b == c
    except:
        print(i + 1)
