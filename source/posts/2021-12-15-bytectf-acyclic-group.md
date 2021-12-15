title: "ByteCTF 2021 Acyclic Group Writeup"
tags:
  - CTF
  - Writeup
#! meta end

一道有趣的 Crypto 题。

#! head end

## 题目大意

程序会进行 256 轮测试，每次测试时，程序会对 $i=1\dots 32$ 随机生成 $c_i\in [1,16]$，然后得到 $N=\prod_{i=1}^{32} p_i^{c_i}$（$p_i$ 是第 $i$ 个质数），接着程序会再次生成一个 $e\in [1,n]$。然后我们有两次机会去询问，每次给出一个 $num$，他会计算 $num^e\bmod n$，最终需要得到 $n$ 的值。

当我们在 256 轮中的正确率达到 80% 时，就可以得到 flag。

## 队友开始时的做法

丢进去一个素数 $p_i$，返回 $m=p_i^e \bmod n$，那么 $\gcd(m,p_i^{16})$ 一定是 $p_i^{c_i}$ 的倍数，但是有可能比 $p_i^{c_i}$ 大。于是可以询问两遍，第一遍询问 $p_1 p_2\dots p_{31}$，第二遍询问 $p_1p_2\dots p_{30}p_{32}$，可以得到一个正确率 60% 的解法。

## 我在此做法上的其他各种想法

- 考虑到有一个 50% 正确率的做法是直接询问 $\prod_{i=1}^{32} p_i^{16}$，有没有办法结合这两个做法，即可达到 80% 正确率？赛后看 [Lord Riot 的 WP](https://lordriot.live/2021/12/13/%E6%91%B8%E9%B1%BCWriteup-3/) 发现，这确实是可行的，只要强制让第一次询问的数 $\bmod p_{32}=-1$ 即可。
- 有没有可能使用离散对数的相关算法强行求出可能的 e，从而检查正确性？经尝试，基本也只能确定上界，对正确率没有显著提升。

## 最终做法

第一遍询问 $a=rand()\cdot \prod_{i=1}^{31}p_i$（此处 $rand$ 返回一个与前 32 个质数均互质的数），得到 $b=a^e\bmod n$。令 $x=\gcd (b,\prod_{i=1}^{31}p_i^{16})$，那么可以发现，$n=\frac{x}{u}\cdot p_{32}^{c_{32}}$，其中 $u$ 的质因子只含前 31 个质数。

经过多次尝试，大多数时候 $u$ 都很小，90% 以上的情况 $u<5000$。而钦定完 $u$ 之后 ，可以找到最小的 $v$，满足 $\frac xu\cdot p_{32}^v>b$，则大概率这个 $v$ 就是 $c_{32}$（概率应该在 99% 以上）。

这样，通过枚举 $u$，我们得到了一个包含几千个 $n_{guess}$ 的列表，其中大概率有真正的 $n$。而我们需要通过第二次询问将这个 $n$ 找出来。

假设我们随机一个数 $y$，然后询问 $a^y\bmod \prod_{i=1}^{32}p_i^{16}$，那么可以得到 $b^y\bmod n$。接下来可以对每个 $n_{guess}$ 计算 $b_y\bmod n_{guess}$，只要和询问结果相同，那么就有可能是真正的 $n$。

于是最后问题只剩下，怎么找到一个足够优秀的 $y$。方法其实也很简单，在本地尝试足够多的 $y$，取信息熵最大的就可以了。实现上，为了卡在 1s 内找到，我开了一台 128 核机子，在每个线程尝试一个区间的 $y$，并且优化了乘法操作用到的数的大小。

## 代码

```python
from pwn import *
from random import randint
from functools import reduce
import random
from gmpy2 import gcd
from multiprocessing import Pool
import time
from copy import deepcopy
from hashlib import sha256

primes = [
    2, 3, 5, 7, 11, 13, 17, 19,
    23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89,
    97, 101, 103, 107, 109, 113, 127, 131,
]

a = set(primes) - {131}


def rand():
    while True:
        x = randint(1, 10**100)
        flag = True
        for p in primes:
            if x % p == 0:
                flag = False
        if flag:
            return x


A = reduce(lambda x, y: x * y, a, 1)
P = reduce(lambda x, y: x * y, primes, 1)
PP = P**16
A = reduce(lambda x, y: x * y, a, 1)
P = reduce(lambda x, y: x * y, primes, 1)
PP = P**16
neg1 = PP - 1


def fac(n):
    res = []
    for p in primes:
        cnt = 0
        while n % p == 0:
            cnt += 1
            n //= p
        res.append(cnt)
    return res


def pow_(x):
    return pow(*x) % x[2]


def nsolve(args):
    r, x1, start, time_limit = args
    _, s, _ = get_s(r, x1)
    etime = time.time() + time_limit
    if start != 1:
        u = set()
        for x in s:
            x[1] = x[1] * pow(x[2], start - 1, x[0]) % x[0]
            u.add(x[1])
        mx = len(u)
        mp = start
    else:
        mx = 0
    while time.time() < etime:
        start += 1
        u = set()
        for x in s:
            x[1] = x[1] * x[2] % x[0]
            u.add(x[1])
        if len(u) > mx:
            mx = len(u)
            mp = start
    return mp, mx


def hash_solve(args):
    prefix, start, len = args
    for i in range(len):
        if sha256(prefix + str(start + i).encode()).hexdigest().startswith('000000'):
            return str(start + i)


def get_s(r, x1):
    possible_n = set()
    for u in range(1, 3000):
        if x1 % u == 0:
            t = x1 // u
            while t <= r:
                t *= 131
            possible_n.add(t)
            #possible_n.add(t * 131)
    # print(_, len(possible_n))
    possible_n = sorted(possible_n)

    ngcd = r
    for x in possible_n:
        ngcd = gcd(ngcd, x)
    ngcd = int(ngcd)
    s = []
    for x in possible_n:
        v = x // ngcd
        assert r // ngcd < v
        rr = r % v
        assert pow(r, 5, x) == pow(rr, 4, v) * (r // ngcd) % v * ngcd
        s.append([v, r // ngcd, rr])
    return ngcd, s, possible_n


if __name__ == '__main__':
    threads = 128
    pool = Pool(threads)
    sock = remote('47.94.165.249', 30001)
    #sock = process(['python', 'acyclic_group.py'])
    sock.recvuntil('SHA256("')
    prefix = sock.recv(8)
    t = 0
    C = 200000
    ans = None
    while True:
        s = pool.map(hash_solve, [(prefix, i * C + t, C)for i in range(threads)])
        for x in s:
            if x is not None:
                ans = x
        t += C * threads
        if ans is not None:
            break
    sock.sendline(ans)

    passed = 0
    start_time = time.time()
    for _ in range(256):
        print('round', _)
        sock.recvuntil('Round ' + str(_) + '\n')
        num = A * rand() % PP
        sock.sendline(str(num))
        r = int(sock.recvline())
        x1 = int(gcd(r, A**16))
        ngcd, s, possible_n = get_s(r, x1)
        sr = pool.map(nsolve, [(r, x1, i * 1000000 + 1, 0.75)for i in range(threads)])
        mx = 0
        for x, y in sr:
            if y > mx:
                mx = y
                mp = x

        num2 = pow(num, mp, PP)
        sock.sendline(str(num2))
        rt = int(sock.recvline())
        #assert rt % ngcd == 0

        ok = []
        for i, (tn, u, v) in enumerate(s):
            if rt == u * pow(v, mp - 1, tn) % tn * ngcd:
                ok.append(i)
        if len(ok) == 0:
            ng = 1
        else:
            # ng = possible_n[random.choice(ok)]
            ng = min(possible_n[x]for x in ok)
            assert pow(r, mp, ng) == rt

        sock.sendline(str(ng))
        if sock.recvuntil('MY FRIEND')[-20:-11] == b'GOOD SHOT':
            passed += 1
            print('passed', end=' ')
        else:
            print('failed', end=' ')
        print(passed, _ + 1, time.time() - start_time)
    sock.interactive()
```
