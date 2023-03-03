from hashlib import sha256

a, b = input(), input()
n = int(input())

assert (
    bin(int(sha256(bytes.fromhex(a)).hexdigest(), 16))[-n:]
    == bin(int(sha256(bytes.fromhex(b)).hexdigest(), 16))[-n:]
)
