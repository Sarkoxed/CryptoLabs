from hashlib import sha256
from sys import argv

base = argv[1]
for n_bit in range(15, 36):
    print(n_bit)
    try:
        with open(f"{base}/collisions_{n_bit}_bit", "rt") as f:
            s = f.read().split("\n")[1:-1]
        for ab in s:
            a, b = ab.split()
            a = bytes.fromhex(a)
            b = bytes.fromhex(b)

            a = sha256(a).hexdigest()
            b = sha256(b).hexdigest()

            a = int(a, 16)
            b = int(b, 16)

            a = a % (1 << n_bit)
            b = b % (1 << n_bit)
            assert a == b
    except Exception as e:
        print(e, "HERE")
        exit(1)
