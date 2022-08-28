title: "CTFZone 2022 Writeup"
tags:
  - CTF
  - Writeup
#! meta end

Writeup for SignatureZone, Yet Another Des and Padic in CTFZone 2022.

#! head end

## SignatureZone

It only checks the aggregated signature, but not the user one. So we just need to make the aggregated signature and public key to values that are controlled by us.

```python
from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls.g2_primitives import pubkey_to_G1, G1_to_pubkey, signature_to_G2, G2_to_signature
from py_ecc.optimized_bls12_381 import add, neg
import json, requests

pubkey = []
sig = []
for i in range(1, 11):
    r = requests.get('https://sigzone.ctfz.one/api/pubkey/%d' % i).json()
    pubkey.append(bytes.fromhex(r['pubkey']))
    r = requests.get('https://sigzone.ctfz.one/api/sig/%d' % i).json()
    sig.append(bytes.fromhex(r['sig']))

agg_pk = bls_pop._AggregatePKs(pubkey)
agg_sig = bls_pop.Aggregate(sig)

sk = 1337
tgt_pk = bls_pop.SkToPk(sk)
message = str.encode(json.dumps({'flag': True}))
tgt_sig = bls_pop.Sign(sk, message)

s_pk = G1_to_pubkey(add(pubkey_to_G1(tgt_pk), neg(pubkey_to_G1(agg_pk))))
s_sig = G2_to_signature(add(signature_to_G2(tgt_sig), neg(signature_to_G2(agg_sig))))

print(requests.post('https://sigzone.ctfz.one/api/validate', json={'signature': s_sig.hex(), 'message': message.hex(), 'pubkey': s_pk.hex()}).text)
```

## Yet Another Des

The file is packed using PyInstaller, thus we can unpack it using pyinstxtractor, and then decompile with uncompyle6.

As the problems says, it's just some DES like algorithm, and we can implement the reversed algorithm.

```python
def invperm(s):
    n = len(s)
    r = [0] * n
    for i in range(n):
        r[s[i]] = i
    return r


def invdes(ret, key_array):
    t = permutation(ret, invperm(INVERSE_PERMUTATION))
    right = t[:32]
    left = t[32:]
    for j, i in list(zip(range(1, 17), key_array))[::-1]:
        old_right = left
        old_left = xor(right, f(old_right, i))
        left, right = old_left, old_right
    return left + right


flag = '7cd245e589aa384ac19dddfafb189650e8c1e6eb13fd52bc'
res = []
for i in range(0, len(flag), 16):
    bin_key = to_bin(KEY)
    permuted_key = permutation(bin_key, PERMUTED_CHOICE_1)
    key_list = key_gen(permuted_key[:len(permuted_key) // 2], permuted_key[len(permuted_key) // 2:])
    block = invdes(to_bin(flag[i:i + 16]), key_list)
    block = permutation(block, invperm(INITIAL_PERMUTATION))
    res.append(''.join([hex(int(i, 2))[2:].zfill(2).lower() for i in wrap(block, 8)]))
print(bytes.fromhex(''.join(res)))
```

## Padic

`padic.py` implements p-adic computations.

In `main.py`, the message is divided in blocks, and for each block, it's converted into an p-adic integer $pt$, and then the encrypted message is $ct=pt/key$, where $key$ is another p-adic integer.

By simple observation, the maximum value in the encrypted message is $96$, and we can know that $p=97$ in our p-adic arithmetic. The precision of `padic.py` is 128 digits, that is, $97^{128}$, while our raw message and key should be very small, say $256^{30}$, so we can try to find small $k$ that $ct\cdot k$ is small enough.

I don't know how to check if the digits are small enough, but I think it's enough to make sure that the $70$~$127$ digits are zero in $ct\cdot k$.

The $i$-th digit of $ct\cdot k$ is:

$$
\left\lfloor\frac{\sum_{j=0}^i\sum_{l=0}^{i-j} k_j \cdot ct_l\cdot p^{j+l}}{p^i}\right\rfloor\bmod p
$$

And in fact, we need:

$$
0\le \left(\sum_{j=0}^i\sum_{l=0}^{i-j} k_j \cdot ct_l\cdot p^{j+l}\right)-N\cdot p^{i+1}< p^i
$$

where N is some arbitrary value. The expression will be very close to 0, since the digits $i-1$, $i-2$, ... are also zero in the real cases.

Thus we can use LLL to optimize this expression to be close to 0.

In my actual solution, I only considered the contribution of items with large enough $p^{j+l}$.

```python
from sage.all import *
import padic

p = 97
s = list(map(lambda x: x.strip(), open('cyphertext.txt').readlines()))
s2 = []
for x in s:
    s2.append(padic.Padic.undump(x, p))

ua = []

K = 10

for j in range(11):
    b = s2[j].mantissa
    for k in range(70, 128 - K):
        a = [0] * 128
        for g in range(K):
            for i in range(k + g + 1):
                a[i] += b[k + g - i] * p**g
        ua.append(a)

n = 30
m = 70
U = 1

M = []
for i in range(n):
    t = [0] * n
    t[i] = U
    for j in range(m):
        t.append(ua[j][i])
    t.append(0)
    M.append(t)
for i in range(m):
    t = [0] * (n + m + 1)
    t[i + n] = p**g
    M.append(t)

M.append([-49 * U] * n + [200] * m + [p**(g + 1)])

M = Matrix(M)
M = M.LLL()

t = list(M[-1])

a = [0] * 128
for i in range(30):
    a[i] = t[i] + 49

k_padic = padic.Padic(p, 128)
k_padic.mantissa = a

u = []
for ct in s2:
    t = (ct * k_padic).get_value()
    u.append(t)

g = 0
for x in u:
    g = gcd(g, x)

flag = b''
for x in u:
    flag += int(x // g).to_bytes(4, 'big')
print(flag)
```
